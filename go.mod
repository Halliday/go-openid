module github.com/halliday/go-openid

go 1.18

replace github.com/halliday/go-errors => ../go-errors

replace github.com/halliday/go-module => ../go-module

replace github.com/halliday/go-tools => ../go-tools

replace github.com/halliday/go-router => ../go-router

replace github.com/halliday/go-rpc => ../go-rpc

replace github.com/halliday/go-values => ../go-values

require (
	github.com/golang-jwt/jwt/v4 v4.4.1
	github.com/google/uuid v1.3.0 // indirect
	github.com/halliday/go-module v1.0.0
	github.com/halliday/go-router v1.0.0
	github.com/halliday/go-rpc v1.0.0
	github.com/halliday/go-tools v1.0.0
)

require (
	github.com/halliday/go-errors v1.0.0 // indirect
	github.com/halliday/go-values v1.0.0 // indirect
)
