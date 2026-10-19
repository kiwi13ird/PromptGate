"""Private, bounded durable event delivery. No network work in enqueue().

Undelivered rows are never evicted. Capacity/disk errors are observable and must
not change enforcement. Credentials/URLs are read by the sender, not persisted.
"""
from __future__ import annotations
import hashlib
from contextlib import contextmanager
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from dashboard_event_sender import DeliveryResult, send_dashboard_event


class EventOutbox:
    def __init__(self, path=None, *, sender=send_dashboard_event, max_rows=10000,
                 max_bytes=100*1024*1024, clock=time.time):
        self.path=Path(path or os.getenv('DASHBOARD_OUTBOX_PATH') or Path(__file__).parent/'var/dashboard-outbox/events.sqlite3')
        self.sender=sender; self.max_rows=max_rows; self.max_bytes=max_bytes; self.clock=clock
        self.lock=threading.RLock(); self.wake=threading.Event(); self.halt=threading.Event()
        self.thread=None; self.errors=0

    def _connect(self):
        if not self.path.parent.exists(): self.path.parent.mkdir(parents=True,mode=0o700)
        if not self.path.exists():
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.close(fd)
        conn=sqlite3.connect(self.path,timeout=0.1)
        conn.execute('PRAGMA journal_mode=WAL'); conn.execute('PRAGMA synchronous=FULL')
        conn.executescript('''CREATE TABLE IF NOT EXISTS queue(
          id TEXT PRIMARY KEY, digest TEXT NOT NULL, payload TEXT NOT NULL,
          created REAL NOT NULL, next_at REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
          state TEXT NOT NULL DEFAULT 'pending', last_status INTEGER);
          CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY,digest TEXT NOT NULL,at REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);''')
        return conn

    @contextmanager
    def _db(self):
        conn=self._connect()
        try:
            with conn: yield conn
        finally: conn.close()

    @staticmethod
    def _count(conn,name):
        conn.execute('INSERT INTO counters VALUES(?,1) ON CONFLICT(name) DO UPDATE SET value=value+1',(name,))

    def enqueue(self,event):
        try:
            event_id=event.get('eventId')
            if not isinstance(event_id,str) or not 1<=len(event_id)<=200: raise ValueError('invalid id')
            payload=json.dumps(event,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
            size=len(payload.encode()); digest=hashlib.sha256(payload.encode()).hexdigest()
            if size>256*1024: raise ValueError('payload limit')
            with self.lock,self._db() as conn:
                known=conn.execute('SELECT digest FROM queue WHERE id=? UNION ALL SELECT digest FROM receipts WHERE id=?',(event_id,event_id)).fetchall()
                if known:
                    if any(row[0]!=digest for row in known):
                        self._count(conn,'conflicts'); return DeliveryResult('conflict')
                    return DeliveryResult('duplicate')
                count,used=conn.execute('SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM queue').fetchone()
                if count>=self.max_rows or used+size>self.max_bytes:
                    self._count(conn,'capacity_rejections'); return DeliveryResult('full')
                now=self.clock()
                conn.execute('INSERT INTO queue(id,digest,payload,created,next_at) VALUES(?,?,?,?,?)',(event_id,digest,payload,now,now))
            self.wake.set(); return DeliveryResult('queued')
        except Exception:
            self.errors+=1; return DeliveryResult('unavailable')

    def deliver_once(self):
        # The lock protects only short SQLite operations, never HTTP.
        with self.lock,self._db() as conn:
            row=conn.execute("SELECT id,digest,payload,attempts FROM queue WHERE state='pending' AND next_at<=? ORDER BY created LIMIT 1",(self.clock(),)).fetchone()
        if not row: return False
        event_id,digest,payload,attempts=row
        try: result=self.sender(json.loads(payload))
        except Exception: result=DeliveryResult('failed')
        now=self.clock(); status=getattr(result,'http_status',None)
        with self.lock,self._db() as conn:
            if result.status=='sent':
                conn.execute('INSERT OR IGNORE INTO receipts VALUES(?,?,?)',(event_id,digest,now))
                conn.execute('DELETE FROM queue WHERE id=? AND digest=?',(event_id,digest))
                self._count(conn,'delivered')
                # Receipts contain hashes only. Undelivered payloads are retained.
                conn.execute('DELETE FROM receipts WHERE at<?',(now-7*86400,))
                conn.execute('DELETE FROM receipts WHERE id IN (SELECT id FROM receipts ORDER BY at DESC LIMIT -1 OFFSET 20000)')
            else:
                blocked=status in (400,404,409,413,415,422)
                delay=60 if status in (401,403) else min(60,2**min(attempts+1,6))
                conn.execute('UPDATE queue SET attempts=attempts+1,next_at=?,state=?,last_status=? WHERE id=?',(now+delay,'blocked' if blocked else 'pending',status,event_id))
                self._count(conn,'retries')
        return True

    def snapshot(self):
        try:
            with self.lock,self._db() as conn:
                pending,blocked,oldest=conn.execute("SELECT sum(state='pending'),sum(state='blocked'),min(created) FROM queue").fetchone()
                counts=dict(conn.execute('SELECT name,value FROM counters'))
            return {'storage_ready':True,'pending':pending or 0,'blocked':blocked or 0,
                    'oldest_age_sec':max(0,self.clock()-oldest) if oldest is not None else 0,
                    'delivered':counts.get('delivered',0),'retries':counts.get('retries',0),
                    'capacity_rejections':counts.get('capacity_rejections',0),'conflicts':counts.get('conflicts',0),'enqueue_errors':self.errors}
        except Exception: return {'storage_ready':False,'enqueue_errors':self.errors}

    def start(self):
        with self.lock:
            if self.thread and self.thread.is_alive(): return
            self.halt.clear(); self.thread=threading.Thread(target=self._run,daemon=True,name='dashboard-event-outbox');self.thread.start()

    def stop(self):
        self.halt.set();self.wake.set()
        if self.thread and self.thread is not threading.current_thread(): self.thread.join(timeout=1)

    def _run(self):
        while not self.halt.is_set():
            try:
                if self.deliver_once(): continue
            except Exception: self.errors+=1
            self.wake.wait(timeout=1);self.wake.clear()
