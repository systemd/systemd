; Sets emacs variables based on mode.
; A list of (major-mode . ((var1 . value1) (var2 . value2)))
; Mode can be nil, which gives default values.

; Note that we set a line width of 119 for .c and XML files, but for everything
; else (such as journal catalog files, unit files, README files) we stick to a
; more conservative 79 characters.

; NOTE: If you update this file make sure to update .vimrc and .editorconfig,
; too.

((nil . ((indent-tabs-mode . nil)
         (tab-width . 8)
         (fill-column . 79)))
 (c-mode . ((fill-column . 119)
            (c-basic-offset . 8)
            (eval . (c-set-offset 'substatement-open 0))
            (eval . (c-set-offset 'statement-case-open 0))
            (eval . (c-set-offset 'case-label 0))
            (eval . (c-set-offset 'arglist-intro '++))
            (eval . (c-set-offset 'arglist-close 0))))
 (nxml-mode . ((nxml-child-indent . 2)
               (fill-column . 119)))
 (meson-mode . ((meson-indent-basic . 8)))
 (sh-mode . ((sh-basic-offset . 8)
             (sh-indentation . 8)))
 (awk-mode . ((c-basic-offset . 8))))
