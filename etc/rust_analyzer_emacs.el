;; copy or link to .dirlocals.el in project root
((rustic-mode . (
                ;; this configuration is used if you use eglot
                 (eglot-workspace-configuration . (:rust-analyzer
                                                   (
                                                    :check (
                                                            :invocationStrategy "once"
                                                            :overrideCommand ["./miri"
                                                                              "clippy"
                                                                              "--message-format=json"])
                                                    :linkedProjects ["Cargo.toml"
                                                                     "cargo-miri/Cargo.toml"
                                                                     "genmc-sys/Cargo.toml"
                                                                     "miri-script/Cargo.toml"]
                                                    :cargo (
                                                            :extraEnv (
                                                                       :MIRI_AUTO_OPS "no"
                                                                       :MIRI_IN_RA "1")
                                                            :buildScripts (
                                                                           :enable t
                                                                           :invocationStrategy "once"
                                                                           :overrideCommand ["./miri"
                                                                                             "check"
                                                                                             "--no-default-features"
                                                                                             "--message-format=json"]))
                                                    :rustc ( :source "discover" ))))
                ;; these  configuration are used if you use lsp-mode
                ; FIXME: lsp mode does not support setting buildScript/check
                 (lsp-rust-analyzer-linked-projects . '(
                                                        "Cargo.toml"
                                                        "cargo-miri/Cargo.toml"
                                                        "genmc-sys/Cargo.toml"
                                                        "miri-script/Cargo.toml" ))
                 (lsp-rust-analyzer-cargo-extra-env . (make-hash-table
                                                       "MIRI_AUTO_OPS" "no"
                                                       "MIRI_IN_RA" "1"))
                 (lsp-rust-analyzer-rustc-source . "discover"))))
