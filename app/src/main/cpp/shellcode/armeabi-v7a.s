        .global _start

        .text
        .thumb_func
_start:
call_code:
    blx r4
break_code:
    bkpt #0
svc_code:
    svc 0