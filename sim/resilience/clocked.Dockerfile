# The server image, plus a way to run a process whose clock can be changed while it runs.
FROM splint-test-server
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libfaketime >/dev/null \
    && ln -s "$(dpkg -L libfaketime | grep -m1 'libfaketime.so.1$')" /usr/local/lib/libfaketime.so.1 \
    && echo +0 > /tmp/splint-clock && chmod 644 /tmp/splint-clock
