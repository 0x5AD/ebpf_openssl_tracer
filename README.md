# Openssl Tracer: a TLS protocol tracer based on eBPF

## Dependencies:
To use this tool, you will need to install a recent version of python3 and follow the installation steps of the [bcc toolkit](https://github.com/iovisor/bcc/).

## Usage:
Once you have downloaded the openssltracer.py script, you just need to run it with a Python 3 interpreter as superuser to use the tool. 
```
sudo python3 openssltrace.py
OR
chmod +x openssltrace.py; sudo ./openssltrace.py
```

## Example:
Terminal 1:
```
sad@sad-lab:~/ebpf_openssl_tracer(main)$ sudo ./openssltrace.py 
Hit Ctrl-C to exit
PID    COMM  IP  SADDR                                   LPORT  DADDR                     DPORT 
1846   curl   4  192.168.1.2                             57038  163.172.43.202            443   
1856   curl   6  2a01:cb19:8667:1700:ca4c:be8a:888c:dc1c 53100  2a02:26f0:2b00:382::c1e   443
```
Terminal 2:
```
sad@sad-lab:~/ebpf_openssl_tracer(main)$ curl https://quarkslab.com
/* SNIP */
sad@sad-lab:~/ebpf_openssl_tracer(main)$ curl https://www.openssl.org
/* SNIP */
```

## Ressources:
- Intercepting Zoom's encrypted data with BPF. Alessandro Decina: https://confused.ai/posts/intercepting-zoom-tls-encryption-bpf-uprobes
- Debugging with eBPF Part 3: Tracing SSL/TLS connectionsPermalink. Omid Azizi: https://blog.px.dev/ebpf-openssl-tracing/
- tcpconnect tool: https://github.com/iovisor/bcc/blob/master/tools/tcpconnect.py
