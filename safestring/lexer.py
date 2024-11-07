from enum import Enum

class TokenType(Enum):
    GROUP = "GROUP"
    IDENTIFIER = "IDENTIFIER"
    EQUALS = "="
    COLON = ":"
    COMMA = ","
    SEMICOLON = ";"
    LEFT_BRACKET = "["
    RIGHT_BRACKET = "]"
    LEFT_BRACE = "{"
    RIGHT_BRACE = "}"
    TYPE_ACCOUNT = "ACCOUNT"
    TYPE_PASSWORD = "PASSWORD"
    TYPE_GENERIC = "GENERIC"
    COMMENT = "#"
    NEWLINE = "\n"
    WHITESPACE = "WHITESPACE"
    EOF = "EOF"

class Token:
    def __init__(self, type: TokenType, value: str, line: int, column: int):
        self.type = type
        self.value = value
        self.line = line
        self.column = column

class Lexer:
    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.current_char = self.text[0] if text else None
        self.line = 1
        self.column = 1

    def advance(self):
        self.pos += 1
        if self.pos > len(self.text) - 1:
            self.current_char = None
        else:
            if self.current_char == '\n':
                self.line += 1
                self.column = 1
            else:
                self.column += 1
            self.current_char = self.text[self.pos]

    def skip_whitespace(self):
        while self.current_char and self.current_char.isspace():
            self.advance()

    def get_identifier(self):
        result = ''
        valid_chars = '@._-'  # Add valid special characters for identifiers
        while self.current_char and (self.current_char.isalnum() or self.current_char in valid_chars):
            result += self.current_char
            self.advance()
        return result

    def get_next_token(self) -> Token:
        while self.current_char:
            if self.current_char.isspace():
                self.skip_whitespace()
                continue

            if self.current_char.isalnum() or self.current_char in '@._-':
                value = self.get_identifier()
                if value.lower() == 'group':
                    return Token(TokenType.GROUP, value, self.line, self.column)
                return Token(TokenType.IDENTIFIER, value, self.line, self.column)

            if self.current_char == '=':
                self.advance()
                return Token(TokenType.EQUALS, '=', self.line, self.column)

            if self.current_char == ':':
                self.advance()
                return Token(TokenType.COLON, ':', self.line, self.column)

            if self.current_char == ',':
                self.advance()
                return Token(TokenType.COMMA, ',', self.line, self.column)

            if self.current_char == ';':
                self.advance()
                return Token(TokenType.SEMICOLON, ';', self.line, self.column)

            if self.current_char == '[':
                self.advance()
                return Token(TokenType.LEFT_BRACKET, '[', self.line, self.column)

            if self.current_char == ']':
                self.advance()
                return Token(TokenType.RIGHT_BRACKET, ']', self.line, self.column)

            if self.current_char == '{':
                self.advance()
                return Token(TokenType.LEFT_BRACE, '{', self.line, self.column)

            if self.current_char == '}':
                self.advance()
                return Token(TokenType.RIGHT_BRACE, '}', self.line, self.column)

            raise SyntaxError(f"Invalid character: {self.current_char}")

        return Token(TokenType.EOF, '', self.line, self.column)