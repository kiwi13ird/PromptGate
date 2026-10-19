import {z} from 'zod';
import {httpClient} from '@/src/api/httpClient';
import {parseApiResponse} from '@/src/api/schemas';
const lookup=z.object({status:z.enum(['FOUND','WAITING','AMBIGUOUS']),count:z.number().int().nonnegative(),checked_at:z.string(),items:z.array(z.object({event_id:z.string().min(1),request_id:z.string().optional(),client_id:z.string(),occurred_at:z.string(),final_action:z.enum(['BLOCK','MASK','ALLOW']),target_llm:z.string(),content_type:z.string().optional()}))});
export type LookupKind='request'|'client'|'event';
export type LookupResult=z.infer<typeof lookup>;
export const demoToolsService={
  async lookup(kind:LookupKind,value:string,since?:string,signal?:AbortSignal){
    const params=new URLSearchParams({kind,value});if(since)params.set('since',since);
    return parseApiResponse(lookup,await httpClient.get<unknown>(`/api/events/lookup?${params}`,signal));
  },
};
