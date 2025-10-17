package com.leocodelab.owaspzap.controllers

import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.*
import org.springframework.jdbc.core.JdbcTemplate

@RestController
@RequestMapping("/api/auth")
class LoginController(private val jdbcTemplate: JdbcTemplate) {

    @PostMapping("/login-vulnerable")
    fun loginVulnerable(
        @RequestParam username: String,
        @RequestParam password: String
    ): Map<String, Any> {
        val query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'"

        return try {
            val users = jdbcTemplate.queryForList(query)

            if (users.isNotEmpty()) {
                mapOf(
                    "success" to true,
                    "message" to "Login bem-sucedido",
                    "user" to users[0]
                )
            } else {
                mapOf(
                    "success" to false,
                    "message" to "Credenciais inválidas"
                )
            }
        } catch (e: Exception) {
            mapOf(
                "success" to false,
                "message" to "Erro no login: ${e.message}"
            )
        }
    }

    @GetMapping("/profile-vulnerable")
    fun profileVulnerable(
        @RequestParam name: String,
        response: HttpServletResponse
    ): String {
        response.contentType = "text/html"
        return """
            <html>
                <body>
                    <h1>Bem-vindo, $name!</h1>
                    <p>Seu perfil foi carregado com sucesso.</p>
                </body>
            </html>
        """.trimIndent()
    }

    @PostMapping("/update-password-vulnerable")
    fun updatePasswordVulnerable(
        @RequestParam userId: String,
        @RequestParam newPassword: String
    ): Map<String, Any> {
        val query = "UPDATE users SET password = ? WHERE id = ?"
        jdbcTemplate.update(query, newPassword, userId)

        return mapOf(
            "success" to true,
            "message" to "Senha atualizada"
        )
    }

    @GetMapping("/users-list-vulnerable")
    fun usersListVulnerable(): List<Map<String, Any>> {
        val query = "SELECT id, username, email, password, credit_card FROM users"
        return jdbcTemplate.queryForList(query)
    }

    @PostMapping("/login-secure")
    fun loginSecure(
        @RequestParam username: String,
        @RequestParam password: String
    ): Map<String, Any> {
        val query = "SELECT * FROM users WHERE username = ? AND password = ?"

        return try {
            val users = jdbcTemplate.queryForList(query, username, password)

            if (users.isNotEmpty()) {
                mapOf(
                    "success" to true,
                    "message" to "Login bem-sucedido"
                )
            } else {
                mapOf(
                    "success" to false,
                    "message" to "Credenciais inválidas"
                )
            }
        } catch (e: Exception) {
            mapOf(
                "success" to false,
                "message" to "Erro no login"
            )
        }
    }
}