# Handout

A combination authoritative nameserver and webserver for Handshake, with DNSSEC and DANE.

---


### 1. Install

Follow the [install guide](INSTALL.md) if you need help.

```
npm i
```

### 2. Configure

A built-in script will take your domain name and IP as parameters, and generate
all the configuration files necessary, including DNSSEC keys. No trailing dot
is necessary. You can use `127.0.0.1` to test locally.

```
node scripts/hnssec-gen.js examplename 127.0.0.1
```

Output should resemble the following. DNSSEC keys are saved to the `conf/` directory,
a configuration file `handout.conf` is generated and a backup record set is saved
at `hsw-rpc_sendupdate.txt`.

```
Writing new conf/handout.conf...

DS record for root zone:
examplename. 172800 IN DS 24620 8 2 297595DC199B947AA8650923619436FBDFD99FD625195111AB4EFE95 0900CADE  ; alg = RSASHA256 ; hash = SHA256

GLUE4 record, Bob format:
ns.examplename. 127.0.0.1

DS record, Bob format:
24620 8 2 297595dc199b947aa8650923619436fbdfd99fd625195111ab4efe950900cade

All records, hsw-rpc sendupdate format:
{"records":[{"type":"GLUE4","ns":"ns.examplename.","address":"127.0.0.1"},{"type":"DS","keyTag":24620,"algorithm":8,"digestType":2,"digest":"297595dc199b947aa8650923619436fbdfd99fd625195111ab4efe950900cade"}]}
```

BACKUP your `conf/` directory at this point! There are private keys in there :-)

### 3. Update your domain on Handshake

The configuration script outputs a complete JSON string for use with hsd rpc calls,
or as separate strings for use with [Bob](https://github.com/kyokan/bob-wallet).
These DNS records authorize your nameserver and provide public key hashes for DNSSEC.

```
hsw-rpc sendupdate examplename \
'{"records":[{"type":"GLUE4","ns":"ns.examplename.","address":"127.0.0.1"}, \
{"type":"DS","keyTag":24620,"algorithm":8,"digestType":2, \
"digest":"297595dc199b947aa8650923619436fbdfd99fd625195111ab4efe950900cade"}]}'
```

### 4. Run

By default the nameserver listens on port `53` (might require sudo) and the HTTPS webserver
listens on port `443`. Add the flag `--test` and the nameserver will listen on port `53530`
instead. An extra HTTP (unencrypted) webserver listens on port `80` just to redirect users to the HTTPS website. `sudo` may be required to access low port numbers,other options may be available.

```
sudo node lib/handout.js
```

Example logging output, indicating source of each request:

```
$ node lib/handout.js 
[debug] (webserver) Webserver opened at host 100.200.10.20
[debug] (authns) Authoritative Nameserver opened for domain examplename.
[debug] (authns) 200.10.100.5 req: examplename. IN A
[debug] (webserver) 200.10.100.5 req: index.html (200)
[debug] (webserver) 200.10.100.5 req: /about.html (200)
[debug] (webserver) 200.10.100.5 req: /img/kitty.png (200)
[debug] (webserver) 200.10.100.5 req: /path/to/nowhere.html (404)
```

### 5. Browse to your website!

From a computer configured to resolve Handshake domains, you should be able to visit your website at

[https://examplename/](https://examplename/)

### 6. Personalize

Your website's root directory is inside this repo at `html/`. Edit the files in there to build your Handshake website!
By default only static pages are supported, but the webserver at `lib/webserver.js` can be configured for more dynamic applicaitons.

## Use your own server

Use handout to generate everything you need to run your own nameserver using BIND9:

- Follow above steps 1, 2 and 3
- Execute: `node scripts/printzone.js`

This will save a zone file at `conf/examplename.zone`.
There is an exmple output file in [docs/test.zone](docs/test.zone).
Check your file with BIND9:

```
$ named-checkzone test docs/test.zone

zone test/IN: loaded serial 1602942956
OK
```

This should be the only file you need to serve your zone with BIND9. Note that
the handout AuthNS can sign wildcard records on the fly. If you are using subdomains
this will require extra steps.


