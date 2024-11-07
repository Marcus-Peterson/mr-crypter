from dataclasses import dataclass
from typing import List, Optional
from safestring.lexer import Lexer, TokenType, Token

@dataclass
class Entry:
    identifier: str
    value: str
    entry_type: List[str]

@dataclass
class Group:
    name: str
    entries: List[Entry]

class Parser:
    def __init__(self, lexer: Lexer):
        self.lexer = lexer
        self.current_token = self.lexer.get_next_token()

    def eat(self, token_type: TokenType):
        if self.current_token.type == token_type:
            self.current_token = self.lexer.get_next_token()
        else:
            raise SyntaxError(f"Expected {token_type}, got {self.current_token.type}")

    def parse_entry(self) -> Entry:
        self.eat(TokenType.LEFT_BRACKET)
        identifier = self.current_token.value
        self.eat(TokenType.IDENTIFIER)
        self.eat(TokenType.EQUALS)
        value = self.current_token.value
        self.eat(TokenType.IDENTIFIER)
        self.eat(TokenType.RIGHT_BRACKET)
        self.eat(TokenType.COLON)
        
        entry_types = []
        entry_types.append(self.current_token.value)
        self.eat(TokenType.IDENTIFIER)
        
        while self.current_token.type == TokenType.COMMA:
            self.eat(TokenType.COMMA)
            entry_types.append(self.current_token.value)
            self.eat(TokenType.IDENTIFIER)
            
        self.eat(TokenType.SEMICOLON)
        
        return Entry(identifier, value, entry_types)

    def parse_group(self) -> Group:
        if self.current_token.type == TokenType.EOF:
            raise EOFError()
        
        self.eat(TokenType.GROUP)
        group_name = self.current_token.value
        self.eat(TokenType.IDENTIFIER)
        self.eat(TokenType.LEFT_BRACE)
        
        entries = []
        while self.current_token.type != TokenType.RIGHT_BRACE:
            if self.current_token.type == TokenType.LEFT_BRACKET:
                entries.append(self.parse_entry())
            elif self.current_token.type == TokenType.EOF:
                raise SyntaxError("Unexpected end of file: missing closing brace")
            else:
                self.advance()
        
        self.eat(TokenType.RIGHT_BRACE)
        return Group(group_name, entries)

    def advance(self):
        self.current_token = self.lexer.get_next_token()