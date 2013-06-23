type ctx
external context:  string -> int -> int -> string -> ctx = "new_Context"

let _ = context "" 75 0 "Crypto-Pro CSP"
