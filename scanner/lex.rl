package scanner

import (
    "fmt"
    "encoding/hex"
    "strconv"
    "strings"
    "github.com/shankarapailoor/moonshine/strace_types"
)

%%{
    machine strace;
    write data;
    access lex.;
    variable p lex.p;
    variable pe lex.pe;
}%%

type lexer struct {
    result *strace_types.Syscall
    data []byte
    p, pe, cs int
    ts, te, act int
}

func newLexer (data []byte) *lexer {
    lex := &lexer {
        data: data,
        pe: len(data),
    }

    %% write init;
    return lex
}

func (lex *lexer) Lex(out *StraceSymType) int {
    eof := lex.pe
    tok := 0
    %%{
        date = digit{4}.'-'.digit{2}.'-'.digit{2};
        nullptr = "NULL";
        time = digit{2}.':'.digit{2}.':'.digit{2}.'+'.digit{4}.'.'.digit+ |
            digit{2}.':'.digit{2}.':'.digit{2}.'+'.digit{4};
        datetime = date.'T'.time;
        unfinished = '<unfinished ...>' | ',  <unfinished ...>';
        or = 'or';
        keyword = 'sizeof' | 'struct';
        identifier = ([A-Za-z].[0-9a-z'_'\*\.\-]*) - keyword - or;
        resumed = '<... '.identifier+.' resumed>'
                    | '<... '.identifier+.' resumed> ,'
                    | '<... resuming'.' '.identifier.' '.identifier.' '.'...>';
        ipv4 = '\"'.digit{1,4}.'\.'.digit{1,4}.'\.'digit{1,4}.'\.'.digit{1,4}'\"';
        ipv6 = '\"'.':'.':'.'\"' | '\"'.':'.':'.digit.'\"';
        mac = xdigit{2}.':'.xdigit{2}.':'.xdigit{2}.':'.xdigit{2}.':'.xdigit{2}.':'.xdigit{2};
        comment := |*
            ((any-"*\/"));
            "*\/" => {fgoto main;};
        *|;

        main := |*
            [+\-]?[1-9].[0-9]* => {out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 10, 64); tok = INT;fbreak;};
            [+\-]?digit . '.' . digit* => {out.val_double, _ = strconv.ParseFloat(string(lex.data[lex.ts : lex.te]), 64); tok= DOUBLE; fbreak;};
            [0].[0-7]* => {out.val_int, _ = strconv.ParseInt(string(lex.data[lex.ts : lex.te]), 8, 64); tok = INT; fbreak;};
            '0x'xdigit+ => {out.val_uint, _ = strconv.ParseUint(string(lex.data[lex.ts:lex.te]), 0, 64); tok = UINT;fbreak;};
            ipv4 => {out.data = string(lex.data[lex.ts+1:lex.te-1]); tok=IPV4; fbreak;};
            ipv6 => {out.data = string(lex.data[lex.ts+1:lex.te-1]); tok=IPV6; fbreak;};
            '\"'.[0-9a-zA-Z\/\\\*]*.'\"'.['.']* => {out.data = ParseString(string(lex.data[lex.ts+1:lex.te-1])); tok = STRING_LITERAL;fbreak;};
            nullptr => {tok = NULL; fbreak;};
            (['_']+?upper+ . ['_'A-Z0-9]+)-nullptr => {out.data = string(lex.data[lex.ts:lex.te]); tok = FLAG; fbreak;};
            identifier => {out.data = string(lex.data[lex.ts:lex.te]); tok = IDENTIFIER;fbreak;};
            unfinished => {tok = UNFINISHED; fbreak;};
            resumed => {tok = RESUMED; fbreak;};
            keyword => {tok = KEYWORD; fbreak;};
            mac => {out.data = string(lex.data[lex.ts : lex.te]); tok = MAC; fbreak;};
            or => {tok = OR; fbreak;};
            '=' => {tok = EQUALS;fbreak;};
            '==' => {tok = LEQUAL; fbreak;};
            '(' => {tok = LPAREN;fbreak;};
            '@' => {tok = AT; fbreak;};
            ')' => {tok = RPAREN;fbreak;};
            '[' => {tok = LBRACKET_SQUARE;fbreak;};
            ']' => {tok = RBRACKET_SQUARE;fbreak;};
            '*' => {tok = TIMES; fbreak;};
            '{' => {tok = LBRACKET;fbreak;};
            '}' => {tok = RBRACKET;fbreak;};
            '|' => {tok = OR;fbreak;};
            ':' => {tok = COLON; fbreak;};
            '&' => {tok = AND;fbreak;};
            '!' => {tok = NOT;fbreak;};
            '~' => {tok = ONESCOMP; fbreak;};
            '<<' => {tok = LSHIFT; fbreak;};
            '>>' => {tok = RSHIFT; fbreak;};
            '->' => {tok = ARROW; fbreak;};
            '=>' => {tok = ARROW; fbreak;};
            "||" => {tok = LOR;fbreak;};
            "&&" => {tok = LAND;fbreak;};
            ',' => {tok = COMMA;fbreak;};
            datetime => {out.data = string(lex.data[lex.ts:lex.te]); tok = DATETIME; fbreak;};
            "\/*" => {fgoto comment;};
            "?" => {tok = QUESTION; fbreak;};
            space;
        *|;

        write exec;
      }%%

    return tok;
}

func (lex *lexer) Error(e string) {
    fmt.Println("error:", e)
}

func ParseString(s string) string{
	var decoded []byte
	var err error
	var strippedStr string
	strippedStr = strings.Replace(s, `\x`, "", -1)
	strippedStr = strings.Replace(strippedStr, ".", "", -1)
	strippedStr = strings.Replace(strippedStr, `"`, "", -1)
	if len(strippedStr) % 2 > 0 {
	    strippedStr += "0"
	}
	if decoded, err = hex.DecodeString(strippedStr); err != nil {
		panic(fmt.Sprintf("Failed to decode string: %s, with error: %s\n", s, err.Error()))
	}
	decoded = append(decoded, '\x00')
	return string(decoded)
}
