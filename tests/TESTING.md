# Testing checklist

Record the following for every test binary:

- `file <binary>` architecture
- `objdump -p <binary>` imports/exports
- `./build/peparser <binary>` output
- Whether parser output agrees with the reference tools

Test malformed samples too. Never test untrusted samples on a production machine.
