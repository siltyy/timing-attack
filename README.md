# timing-attack

a program of questionable quality i threw together for a ctf's timing attack
challenge when i got tired of trying to parallelize pwntools.

it's set up to talk to an ssl-enabled tcp server, but it can be modified pretty
easily to support files or whatever else. maybe i'll add support for that
eventually. in the mean time, `socat` is probably a reasonable (if not janky)
solution for local binaries.

i don't plan on actively working on this right now, feel free to contribute
though.
