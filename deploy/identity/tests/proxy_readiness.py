"""Bounded readiness observations for actual TLS proxy acceptance tests only."""
import ssl
import time


def wait_for_proxy(get_status, process, failure_message):
    http_count=0
    transport_count=0
    last_status='UNKNOWN'
    last_transport='NONE'
    for attempt in range(1,51):
        last_status='UNKNOWN'
        last_transport='NONE'
        try:
            status=get_status()
            http_count+=1
            if status==200:
                return
            if isinstance(status,int) and 100<=status<=599:
                last_status=str(status)
        except OSError as error:
            transport_count+=1
            if isinstance(error,ssl.SSLCertVerificationError):
                last_transport='CERTIFICATE_VERIFICATION'
            elif isinstance(error,ssl.SSLError):
                last_transport='TLS'
            elif isinstance(error,TimeoutError):
                last_transport='TIMEOUT'
            elif isinstance(error,ConnectionRefusedError):
                last_transport='CONNECTION_REFUSED'
            else:
                last_transport='OTHER_IO'
        time.sleep(.1)
    exit_code=process.poll()
    process_state='RUNNING' if exit_code is None else str(exit_code)
    raise AssertionError(failure_message+f': attempts={attempt} http={http_count} '
                         f'transport={transport_count} last_status={last_status} '
                         f'last_transport={last_transport} process={process_state}') from None
