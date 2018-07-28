%{
package scanner

import (
    types "github.com/shankarapailoor/moonshine/strace_types"
    //"fmt"
)
%}

%start syscall

%union {
    data string
    val_int int64
    val_double float64
    val_uint uint64
    val_field *types.Field
    val_call *types.Call
    val_macro *types.Macro
    val_int_type *types.IntType
    val_identifiers []*types.BufferType
    val_buf_type *types.BufferType
    val_struct_type *types.StructType
    val_array_type *types.ArrayType
    val_pointer_type *types.PointerType
    val_flag_type *types.FlagType
    val_type types.Type
    val_ip_type *types.IpType
    val_types []types.Type
    val_parenthetical *types.Parenthetical
    val_syscall *types.Syscall
}

%token <data> STRING_LITERAL IPV4 IPV6 IDENTIFIER FLAG DATETIME SIGNAL_PLUS SIGNAL_MINUS MAC
%token <val_int> INT
%token <val_uint> UINT
%token <val_double> DOUBLE
%type <val_field> field_type
%type <val_identifiers> identifiers
%type <val_int_type> int_type
%type <val_buf_type> buf_type
%type <val_struct_type> struct_type
%type <val_array_type> array_type
%type <val_flag_type> flag_type
%type <val_call> call_type
%type <val_parenthetical> parenthetical, parentheticals
%type <val_macro> macro_type
%type <val_type> type, expr_type, flags, ints
%type <val_pointer_type> pointer_type
%type <val_ip_type> ip_type
%type <val_types> types
%type <val_syscall> syscall

%token STRING_LITERAL IPV4 IPV6 MAC IDENTIFIER FLAG INT UINT QUESTION DOUBLE ARROW
%token OR AND LOR TIMES LAND LEQUAL ONESCOMP LSHIFT RSHIFT TIMES NOT
%token COMMA LBRACKET RBRACKET LBRACKET_SQUARE RBRACKET_SQUARE LPAREN RPAREN EQUALS
%token UNFINISHED RESUMED
%token SIGNAL_PLUS SIGNAL_MINUS NULL AT COLON KEYWORD

%nonassoc NOTYPE
%nonassoc FLAG
%nonassoc NOFLAG

%nonassoc EQUAL
%nonassoc ARROW

%left LOR
%left LAND
%left OR
%left AND
%left LEQUAL
%left LSHIFT RSHIFT
%left TIMES
%left ONESCOMP

%%
syscall:
    IDENTIFIER LPAREN UNFINISHED %prec NOFLAG { $$ = types.NewSyscall(-1, $1, nil, int64(-1), true, false);
                                                        Stracelex.(*lexer).result = $$ }
    | IDENTIFIER LPAREN types UNFINISHED %prec NOFLAG { $$ = types.NewSyscall(-1, $1, $3, int64(-1), true, false);
                                                        Stracelex.(*lexer).result = $$ }
    | RESUMED UNFINISHED RPAREN EQUALS QUESTION %prec NOFLAG
        {
            $$ = types.NewSyscall(-1, "tmp", nil, -1, true, true);
            Stracelex.(*lexer).result = $$;
        }
    | IDENTIFIER LPAREN RESUMED RPAREN EQUALS INT %prec NOFLAG
        {
            $$ = types.NewSyscall(-1, $1, nil, int64($6), false, false);
            Stracelex.(*lexer).result = $$;
        }
    | RESUMED RPAREN EQUALS INT %prec NOFLAG { $$ = types.NewSyscall(-1, "tmp", nil, int64($4), false, true);
                                                        Stracelex.(*lexer).result = $$ }
    | RESUMED RPAREN EQUALS UINT %prec NOFLAG { $$ = types.NewSyscall(-1, "tmp", nil, int64($4), false, true);
                                                        Stracelex.(*lexer).result = $$ }
    | RESUMED RPAREN EQUALS QUESTION %prec NOFLAG { $$ = types.NewSyscall(-1, "tmp", nil, -1, false, true);
                                                              Stracelex.(*lexer).result = $$ }
    | RESUMED RPAREN EQUALS INT LPAREN parentheticals RPAREN { $$ = types.NewSyscall(-1, "tmp", nil, int64($4), false, true);
                                                        Stracelex.(*lexer).result = $$ }
    | RESUMED RPAREN EQUALS UINT LPAREN parentheticals RPAREN { $$ = types.NewSyscall(-1, "tmp", nil, int64($4), false, true);
                                                        Stracelex.(*lexer).result = $$ }
    | RESUMED types RPAREN EQUALS INT %prec NOFLAG { $$ = types.NewSyscall(-1, "tmp", $2, int64($5), false, true);
                                                        Stracelex.(*lexer).result = $$ }
    | RESUMED types RPAREN EQUALS UINT %prec NOFLAG { $$ = types.NewSyscall(-1, "tmp", $2, int64($5), false, true);
                                                        Stracelex.(*lexer).result = $$ }
    | RESUMED types RPAREN EQUALS QUESTION %prec NOFLAG { $$ = types.NewSyscall(-1, "tmp", $2, -1, false, true);
                                                        Stracelex.(*lexer).result = $$ }
    | RESUMED types RPAREN EQUALS INT LPAREN parentheticals RPAREN { $$ = types.NewSyscall(-1, "tmp", $2, int64($5), false, true);
                                                        Stracelex.(*lexer).result = $$ }
    | RESUMED types RPAREN EQUALS UINT LPAREN parentheticals RPAREN { $$ = types.NewSyscall(-1, "tmp", $2, int64($5), false, true);
                                                        Stracelex.(*lexer).result = $$ }
    | IDENTIFIER LPAREN RPAREN EQUALS INT %prec NOFLAG { $$ = types.NewSyscall(-1, $1, nil, $5, false, false);
                                                            Stracelex.(*lexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS INT %prec NOFLAG{
                                                        $$ = types.NewSyscall(-1, $1, $3, $6, false, false);
                                                        Stracelex.(*lexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS UINT %prec NOFLAG {
                                                        $$ = types.NewSyscall(-1, $1, $3, int64($6), false, false);
                                                        Stracelex.(*lexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS QUESTION %prec NOFLAG {
                                                            $$ = types.NewSyscall(-1, $1, $3, -1, false, false);
                                                            Stracelex.(*lexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS INT FLAG LPAREN parentheticals RPAREN {
                                                              $$ = types.NewSyscall(-1, $1, $3, $6, false, false);
                                                              Stracelex.(*lexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS UINT FLAG LPAREN parentheticals RPAREN {
                                                              $$ = types.NewSyscall(-1, $1, $3, int64($6), false, false);
                                                              Stracelex.(*lexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS INT LPAREN parentheticals RPAREN {
                                                                  $$ = types.NewSyscall(-1, $1, $3, $6, false, false);
                                                                  Stracelex.(*lexer).result = $$;}
    | IDENTIFIER LPAREN types RPAREN EQUALS UINT LPAREN parentheticals RPAREN {
                                                                  $$ = types.NewSyscall(-1, $1, $3, int64($6), false, false);
                                                                  Stracelex.(*lexer).result = $$;}
    | INT syscall {call := $2; call.Pid = $1; Stracelex.(*lexer).result = call}

parentheticals:
    parenthetical {$$ = types.NewParenthetical();}
    | parentheticals parenthetical {$$ = types.NewParenthetical();}

parenthetical:
    COMMA {$$=types.NewParenthetical();}
    | OR {$$ = types.NewParenthetical();}
    | AND {$$ = types.NewParenthetical();}
    | LSHIFT {$$ = types.NewParenthetical();}
    | RSHIFT {$$ = types.NewParenthetical();}
    | IDENTIFIER {$$ = types.NewParenthetical();}
    | struct_type {$$ = types.NewParenthetical();}
    | array_type {$$ = types.NewParenthetical();}
    | flag_type {$$ = types.NewParenthetical();}
    | int_type {$$ = types.NewParenthetical();}


types:
    type {types := make([]types.Type, 0); types = append(types, $1); $$ = types;}
    | types COMMA type {$1 = append($1, $3); $$ = $1;}


type:
    buf_type {$$ = $1}
    | field_type {$$ = $1}
    | pointer_type {$$ = $1}
    | array_type {$$ = $1}
    | struct_type {$$ = $1}
    | call_type {$$ = $1}
    | ip_type {$$ = $1}
    | expr_type {$$ = $1}
    | expr_type ARROW type {$$ = types.NewDynamicType($1, $3)}
    | ONESCOMP array_type {$$ = $2}


expr_type:
    flags {$$ = types.NewExpression($1)}
    | ints {$$ = types.NewExpression($1)}
    | macro_type {$$ = types.NewExpression($1)}
    | expr_type OR expr_type {$$ = types.NewExpression(types.NewBinop($1, types.OR, $3))}
    | expr_type AND expr_type {$$ = types.NewExpression(types.NewBinop($1, types.AND, $3))}
    | expr_type LSHIFT expr_type {$$ = types.NewExpression(types.NewBinop($1, types.LSHIFT, $3))}
    | expr_type RSHIFT expr_type {$$ = types.NewExpression(types.NewBinop($1, types.RSHIFT, $3))}
    | expr_type LOR expr_type {$$ = types.NewExpression(types.NewBinop($1, types.LOR, $3))}
    | expr_type LAND expr_type {$$ = types.NewExpression(types.NewBinop($1, types.LAND, $3))}
    | expr_type LEQUAL expr_type {$$ = types.NewExpression(types.NewBinop($1, types.LEQUAL, $3))}
    | LPAREN expr_type RPAREN {$$ = $2}
    | expr_type TIMES expr_type {$$ = types.NewExpression(types.NewBinop($1, types.TIMES, $3))}
    | ONESCOMP expr_type {$$ = types.NewExpression(types.NewUnop($2, types.ONESCOMP))}

ints:
    int_type {i := make(types.Ints, 1); i[0] = $1; $$ = i}
    | ints int_type {$$ = append($1.(types.Ints), $2)}

flags:
    flag_type {f := make(types.Flags, 1); f[0] = $1; $$ = f}
    | flags flag_type {$$ = append($1.(types.Flags), $2)}

call_type:
    IDENTIFIER LPAREN types RPAREN {$$ = types.NewCallType($1, $3)}

macro_type:
    FLAG LPAREN types RPAREN {$$ = types.NewMacroType($1, $3)}
    | FLAG LPAREN identifiers RPAREN {$$ = types.NewMacroType($1, nil)}
    | KEYWORD LPAREN KEYWORD IDENTIFIER RPAREN {$$ = types.NewMacroType($4, nil)}

pointer_type:
    AND IDENTIFIER {$$ = types.NullPointer()}
    | AND UINT EQUALS type {$$ = types.NewPointerType($2, $4)}
    | NULL {$$ = types.NullPointer()}

array_type:
    LBRACKET_SQUARE types RBRACKET_SQUARE {arr := types.NewArrayType($2); $$ = arr}
    | LBRACKET_SQUARE RBRACKET_SQUARE {arr := types.NewArrayType(nil); $$ = arr}

struct_type:
    LBRACKET types RBRACKET {$$ = types.NewStructType($2)}
    | LBRACKET types COMMA RBRACKET {$$ = types.NewStructType($2)}
    | LBRACKET RBRACKET {$$ = types.NewStructType(nil)}

field_type:
     IDENTIFIER EQUALS %prec NOTYPE {$$ = types.NewField($1, nil);}
    | IDENTIFIER EQUALS type {$$ = types.NewField($1, $3);}
    | IDENTIFIER COLON type {$$ = types.NewField($1, $3);}
    | IDENTIFIER EQUALS AT type {$$ = types.NewField($1, $4);}

buf_type:
    STRING_LITERAL {$$ = types.NewBufferType($1)}
    | DATETIME {$$ = types.NewBufferType($1)}


int_type:
      INT {$$ = types.NewIntType($1)}
      | UINT {$$ = types.NewIntType(int64($1))}

flag_type:
      FLAG {$$ = types.NewFlagType($1)}

ip_type:
    IPV4 {$$ = types.NewIpType($1)}
    | IPV6 {$$ = types.NewIpType($1)}
    | MAC {$$ = types.NewIpType($1)}

identifiers:
    IDENTIFIER {ids := make([]*types.BufferType, 0); ids = append(ids, types.NewBufferType($1)); $$ = ids}
    | IDENTIFIER identifiers {$2 = append($2, types.NewBufferType($1)); $$ = $2}

