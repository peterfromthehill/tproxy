Usage:

Install the Helm chart: https://github.com/peterfromthehill/tproxy-helm

And use a initContainer and a sidecar to talk to the tproxy.

Example:

    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: app
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: app
      template:
        metadata:
          labels:
            app: app
        spec:
          containers:
          - name: socat
            image: nicolaka/netshoot
            command:
            - sh
            - -c
            - echo -e '3128\n3129\n3130\n8080\n8443' | while read port; do (socat -d -d -d TCP4-LISTEN:$port,fork,reuseaddr TCP4:tproxy:$port &); done && tail -F /dev/null
          - name: hpi  
            image: app
            securityContext:
              capabilities:
                add:
                - NET_ADMIN
              privileged: true  
            volumeMounts: 
              - name: ssl
                mountPath: /etc/ssl/
              - name: ca-volume
                mountPath: /usr/local/share/ca-certificates            
          initContainers:
          - name: init-networking
            image: nicolaka/netshoot
            securityContext:
              capabilities:
                add:
                - NET_ADMIN
              privileged: true
            command:
            - sh
            - -xc
            - iptables -t nat -I OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443
          - name: sslinit
            image: app
            command:
              - sh
              - -xc
              - update-ca-certificates && cp -r /etc/ssl/* /data/
            volumeMounts:
              - name: ca-volume
                mountPath: /usr/local/share/ca-certificates
              - name: ssl
                mountPath: /data
          volumes:
            - name: ssl
              emptyDir: {}
            - name: ca-volume
              configMap:
                name: ca
  
