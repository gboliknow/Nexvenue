// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/api/v1/users/change-password": {
            "post": {
                "description": "This endpoint allows an authenticated user to change their password by providing the current password, a new password, and OTP verification.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Users"
                ],
                "summary": "Change user password",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Bearer Token",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    },
                    {
                        "description": "Password change request data",
                        "name": "passwordChangeRequest",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/models.ChangePasswordRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Password changed successfully",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request payload or permission denied",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Current password is incorrect or OTP validation failed",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Error updating password",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/users/login": {
            "post": {
                "description": "This endpoint allows users to log in using their email or user tag and password. It returns a JWT token upon successful authentication.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Users"
                ],
                "summary": "User login",
                "parameters": [
                    {
                        "description": "Login request data",
                        "name": "loginRequest",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/models.LoginRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "User successfully logged in with JWT token",
                        "schema": {
                            "type": "object",
                            "additionalProperties": true
                        }
                    },
                    "400": {
                        "description": "Invalid request payload",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "User not found or invalid email/password",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/users/register": {
            "post": {
                "description": "This endpoint allows new users to register by providing an email, role, and a valid OTP. It automatically generates a password and sends it to the user's email.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Users"
                ],
                "summary": "Register a new user",
                "parameters": [
                    {
                        "description": "User registration data",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/models.RegisterRequest"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "User created successfully with authentication token",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request payload",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Invalid OTP",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "409": {
                        "description": "Email already exists",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/users/request-reset-password": {
            "post": {
                "description": "This endpoint allows a user to request a password reset by providing their registered email. An OTP will be sent to the email for further verification.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Users"
                ],
                "summary": "Request password reset",
                "parameters": [
                    {
                        "description": "Password reset request data",
                        "name": "resetRequest",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/models.RequestResetPasswordRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OTP sent to email",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request payload",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "404": {
                        "description": "User not found",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Error generating OTP or sending email",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/users/reset-password": {
            "post": {
                "description": "This endpoint allows a user to reset their password by providing their email, OTP, and a new password.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Users"
                ],
                "summary": "Reset user password",
                "parameters": [
                    {
                        "description": "Password reset data",
                        "name": "resetPasswordRequest",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/models.ResetPasswordRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Password reset successfully",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request payload",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Invalid or expired OTP",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "404": {
                        "description": "User not found",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Error hashing password or updating user",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/users/sendOtp": {
            "post": {
                "description": "This endpoint sends a one-time password (OTP) to the specified user's email for verification.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Users"
                ],
                "summary": "Send OTP to user's email",
                "parameters": [
                    {
                        "description": "Email Address",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/models.SendOTPRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OTP sent to email",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request payload",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Failed to send OTP",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/api/v1/users/verify": {
            "post": {
                "description": "This endpoint verifies the OTP sent to the user's email.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Users"
                ],
                "summary": "Verify OTP",
                "parameters": [
                    {
                        "description": "Email and OTP",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/models.VerifyOTPRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OTP verified",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "400": {
                        "description": "Invalid request payload",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "OTP verification failed",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/user/profile": {
            "put": {
                "description": "This endpoint allows users to update their profile information such as FirstName, LastName, Bio, Phone, Address, and ProfilePicture. It also checks if the provided userTag is available before assigning it.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "User"
                ],
                "summary": "Update User Profile",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Bearer token",
                        "name": "Authorization",
                        "in": "header",
                        "required": true
                    },
                    {
                        "description": "User Profile Update",
                        "name": "profile",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/models.ProfileUpdateRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Profile updated successfully",
                        "schema": {
                            "type": "object",
                            "additionalProperties": true
                        }
                    },
                    "400": {
                        "description": "Invalid request payload or permission denied",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "409": {
                        "description": "UserTag is already taken",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "models.ChangePasswordRequest": {
            "type": "object",
            "properties": {
                "current_password": {
                    "type": "string"
                },
                "new_password": {
                    "type": "string"
                },
                "otp": {
                    "type": "string"
                }
            }
        },
        "models.LoginRequest": {
            "type": "object",
            "required": [
                "emailOrUserTag",
                "password"
            ],
            "properties": {
                "emailOrUserTag": {
                    "type": "string"
                },
                "password": {
                    "type": "string"
                }
            }
        },
        "models.ProfileUpdateRequest": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string"
                },
                "bio": {
                    "type": "string"
                },
                "firstName": {
                    "type": "string"
                },
                "lastName": {
                    "type": "string"
                },
                "phone": {
                    "type": "string"
                },
                "profilePicture": {
                    "type": "string"
                },
                "userTag": {
                    "type": "string"
                }
            }
        },
        "models.RegisterRequest": {
            "type": "object",
            "required": [
                "email"
            ],
            "properties": {
                "email": {
                    "type": "string"
                },
                "otp": {
                    "type": "string"
                },
                "role": {
                    "type": "string"
                }
            }
        },
        "models.RequestResetPasswordRequest": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string"
                }
            }
        },
        "models.ResetPasswordRequest": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string"
                },
                "new_password": {
                    "type": "string"
                },
                "otp": {
                    "type": "string"
                }
            }
        },
        "models.SendOTPRequest": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string"
                }
            }
        },
        "models.VerifyOTPRequest": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string"
                },
                "otp": {
                    "type": "string"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "",
	Host:             "",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "",
	Description:      "",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
