from enum import Enum


class TokenStat(Enum):
    PENDING = 1
    STARTED = 2
    FINISHED = 3
    WRONG = 4


class Token:
    def __init__(self):
        self.data = b""

    def add(self, char: bytes):
        self.data = self.data + char

    def delete_last(self, num: int):
        if not num:
            return
        self.data = self.data[0:-num]

    def __bytes__(self) -> bytes:
        return self.data

    def __str__(self) -> str:
        return bytes(self).decode("utf-8")


class Span:
    START = b""
    END = b""
    ESCAPE = b""

    def __init__(self):
        self.data = b""
        self.pending_data = b""
        self.status = None

    def add_char(self, char: bytes):
        self.data = self.data + char

    def add(self, char: bytes) -> TokenStat:
        if self.status == TokenStat.WRONG:
            return self.status

        if (
            not self.status or self.status == TokenStat.PENDING
        ) and not self.START.startswith(self.pending_data + char):
            self.status = TokenStat.WRONG
            return self.status

        if (
            not self.status or self.status == TokenStat.PENDING
        ) and self.START == self.pending_data + char:
            self.pending_data = ""
            self.add_char(char)
            self.status = TokenStat.STARTED
            return self.status

        if (
            not self.status or self.status == TokenStat.PENDING
        ) and self.START.startswith(self.pending_data + char):
            self.pending_data = self.pending_data + char
            self.add_char(char)
            self.status = TokenStat.PENDING
            return self.status

        if self.status == TokenStat.STARTED and (self.data + char).endswith(self.END):
            if not self.ESCAPE or not self.data.endswith(self.ESCAPE):
                self.status = TokenStat.FINISHED
                self.add_char(char)
                return self.status

        self.add_char(char)

    def __bytes__(self) -> bytes:
        return self.data

    def __str__(self) -> str:
        return bytes(self).decode("utf-8")


class StringSpan(Span):
    START = b'"'
    END = b'"'
    ESCAPE = b"\\"


class CommentSpan(Span):
    START = b"//"
    END = b"\n"


class Comment2Span(Span):
    START = b"/*"
    END = b"*/"


class Tokenizer:
    SPANS = (StringSpan, CommentSpan, Comment2Span)

    def __init__(self):
        self.started = None
        self.default_token = Token()
        self.finished_tokens = []
        self.token_candidates = set()

    def process(self, data: bytes, finalize: bool = False):
        for char in data:
            self.add(bytes([char]))
        if finalize:
            self.finalyze()

    def finalyze(self):
        if self.default_token.data:
            self.finished_tokens.append(self.default_token)

    def add(self, char: bytes):
        if self.started:
            status = self.started.add(char)
            if status == TokenStat.FINISHED:
                self.finished_tokens.append(self.started)
                self.started = None
            return

        for span_ins in list(self.token_candidates):
            status = span_ins.add(char)

            if status == TokenStat.STARTED:
                self.default_token.delete_last(len(span_ins.START) - 1)

                if self.default_token.data:
                    self.finished_tokens.append(self.default_token)

                self.default_token = Token()
                self.started = span_ins
                self.token_candidates = set()
                return

            if status == TokenStat.WRONG:
                self.token_candidates.remove(span_ins)

        for span in self.SPANS:
            instance = span()
            status = instance.add(char)

            if status == TokenStat.STARTED:
                self.default_token.delete_last(len(instance.START) - 1)

                if self.default_token.data:
                    self.finished_tokens.append(self.default_token)

                self.default_token = Token()
                self.started = instance
                self.token_candidates = set()
                return

            if status == TokenStat.PENDING:
                self.token_candidates.add(instance)

        self.default_token.add(char)
