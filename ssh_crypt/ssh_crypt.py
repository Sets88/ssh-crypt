import os
import sys
import argparse
from functools import lru_cache
from io import BytesIO
from typing import Optional
from typing import Callable

from paramiko import AgentKey

from .jsonc_tokenizer import Span, StringSpan, CommentSpan, Comment2Span, Tokenizer
from .ciphers import Encryptor, Decryptor, ProcessorsAbc
from .utils import get_first_key, find_filter_key, E


class Processor:
    def __init__(
        self,
        data_processor: Callable[[], ProcessorsAbc],
        input_file: Optional[str],
        output_file: Optional[str],
        string_data: Optional[str],
    ):
        try:
            self.data_processor = data_processor()
        except ValueError as err:
            sys.stderr.write("%s\n" % err)
            exit(1)
        self.input = sys.stdin.buffer
        if string_data:
            self.input = BytesIO(string_data.encode("utf-8"))
        if input_file:
            self.input = open(input_file, "rb")
        self.output = sys.stdout.buffer
        if output_file:
            self.output = open(output_file, "wb")

    def run(self) -> None:
        while True:
            data = self.input.read(4096)

            if not data:
                break

            chunk = self.data_processor.send(data)
            if chunk:
                self.output.write(chunk)
            if len(data) < 4096:
                break
        self.output.write(self.data_processor.send(b""))
        self.output.flush()
        self.output.close()


class ProcessorFifoMode:
    def __init__(
        self,
        data_processor: Callable[[], ProcessorsAbc],
        input_file: Optional[str],
        output_file: Optional[str],
        string_data: Optional[str],
    ):
        self.data_processor = data_processor
        self.input_file = input_file
        self.output_file = output_file
        self.string_data = string_data

    def run(self):
        while True:
            try:
                os.mkfifo(self.output_file)
                processor = Processor(
                    self.data_processor, self.input_file, self.output_file, self.string_data
                )
                processor.run()
            except BrokenPipeError:
                pass
            finally:
                os.unlink(self.output_file)


def create_encr_span(ssh_key: AgentKey):
    class EncrSpan(Span):
        START = b'E"'
        END = b'"'
        ESCAPE = b"\\"

        @staticmethod
        @lru_cache(maxsize=1024)
        def decrypt(data):
            return bytes(E(data, ssh_key=ssh_key))

        def __bytes__(self):
            data_to_decrypt = self.data[2:-1].replace(b"\\\\", b"\\")
            return b'"' + EncrSpan.decrypt(data_to_decrypt) + b'"'

        def __str__(self):
            return bytes(self).decode("utf-8")

    return EncrSpan


class JsonCProcessor(Tokenizer, ProcessorsAbc):
    def __init__(self, ssh_key: AgentKey, binary):
        super().__init__()
        EncrSpan = create_encr_span(ssh_key)
        self.SPANS = (StringSpan, CommentSpan, Comment2Span, EncrSpan)

    def send(self, data):
        if not data:
            self.finalyze()
        else:
            self.process(data)

        data = []

        for token in self.finished_tokens:
            if isinstance(token, (CommentSpan, Comment2Span)):
                continue

            data.append(bytes(token))

        self.finished_tokens = []

        return b"".join(data)


PROCESSORS = {"decrypt": Decryptor, "encrypt": Encryptor, "jsonc": JsonCProcessor}


def main() -> None:
    ssh_key = get_first_key()
    if not ssh_key:
        sys.stderr.write("SSH key not found\n")
        exit(1)

    parser = argparse.ArgumentParser(
        description="Encrypting/Decrypting data using key from ssh-agent"
    )
    parser.add_argument(
        "--encrypt",
        "-e",
        dest="processor",
        action="store_const",
        const="encrypt",
        default="encrypt",
        help="Encrypt incomming data(default)",
    )

    parser.add_argument(
        "--decrypt",
        "-d",
        dest="processor",
        action="store_const",
        const="decrypt",
        default=None,
        help="Decrypt incomming data",
    )

    parser.add_argument("--input", "-i", nargs="?", help="input file")

    parser.add_argument("--output", "-o", nargs="?", help="output file")

    parser.add_argument("--string", "-s", nargs="?", help="input string")

    parser.add_argument("--type", "-t", choices=["jsonc"], dest="type", action="store")

    parser.add_argument(
        "--fifomode",
        "-f",
        action="store_true",
        default=False,
        help="FIFO mode, output file will be created as FIFO file for continuous processing",
    )

    # List all keys fingerprints in md5
    # # ssh-add -l -E md5
    # 2048 MD5:12:34:56:78:90:ab:cd:ef:01:23:34:56:78:90:12:34
    # Public key for PIV Authentication (RSA)
    # --key '12:34:56:78:90:ab:cd:ef:01:23:34:56:78:90:12:34'
    parser.add_argument("--key", "-k", nargs="?", help="Key Filter")

    parser.add_argument(
        "--binary",
        "-b",
        action="store_true",
        default=False,
        help="encrypt into binary data",
    )

    args = parser.parse_args()

    if args.key:
        ssh_key = find_filter_key(args.key)
        if not ssh_key:
            sys.stderr.write("SSH key not found\n")
            exit(1)

    if args.processor:
        data_processor = PROCESSORS[args.processor]

    if args.type:
        data_processor = PROCESSORS[args.type]

    if args.fifomode:
        ProcessorFifoMode(
            lambda: data_processor(ssh_key, args.binary),
            args.input,
            args.output,
            args.string,
        ).run()
    else:
        Processor(
            lambda: data_processor(ssh_key, args.binary),
            args.input,
            args.output,
            args.string,

        ).run()


if __name__ == "__main__":
    main()
