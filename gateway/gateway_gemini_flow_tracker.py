from mitmproxy import http
from urllib.parse import parse_qs
import time


TARGET_HOST = "gemini.google.com"


def print_header(title):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def is_gemini_target(flow):

    req = flow.request

    if req.host != TARGET_HOST:
        return False

    if req.method != "POST":
        return False

    path = req.path

    targets = [
        "batchexecute",
        "StreamGenerate",
        "assistant.lamda",
    ]

    return any(target in path for target in targets)


def request(flow: http.HTTPFlow):

    if not is_gemini_target(flow):
        return

    req = flow.request

    print_header("GEMINI REQUEST FLOW TRACKER")

    print("TIME:")
    print(time.strftime("%H:%M:%S"))

    print("\nFLOW ID:")
    print(flow.id)

    print("\nCLIENT:")
    print(req.host)

    print("\nMETHOD:")
    print(req.method)

    print("\nPATH:")
    print(req.path)

    print("\nCONTENT TYPE:")
    print(req.headers.get("content-type"))

    body = req.get_text()

    print("\nBODY SIZE:")
    print(len(body))

    try:
        form = parse_qs(body)

        print("\nFORM FIELDS:")
        print(list(form.keys()))

        if "f.req" in form:
            freq = form["f.req"][0]

            print("\nf.req LENGTH:")
            print(len(freq))

            print("\nf.req FIRST 300 CHAR:")
            print(freq[:300])

    except Exception as e:

        print("\nFORM PARSE ERROR:")
        print(e)

    print_header("END REQUEST")


def response(flow: http.HTTPFlow):

    if not is_gemini_target(flow):
        return

    res = flow.response

    print_header("GEMINI RESPONSE FLOW TRACKER")

    print("FLOW ID:")
    print(flow.id)

    print("\nSTATUS:")
    print(res.status_code)

    print("\nPATH:")
    print(flow.request.path)

    print("\nRESPONSE TYPE:")
    print(res.headers.get("content-type"))

    print("\nRESPONSE SIZE:")
    print(len(res.content))

    print_header("END RESPONSE")
