FROM busybox

ADD shadowgate /bin/shadowgate

ENTRYPOINT ["/bin/shadowgate"]

