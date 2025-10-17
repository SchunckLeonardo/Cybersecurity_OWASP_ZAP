package com.leocodelab.owaspzap.controllers

import com.leocodelab.owaspzap.entities.AuthRequestDTO
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

val usersAllowed = mutableListOf("admin", "user1", "user2")
val passwordsAllowed = mutableListOf("admin", "user1", "user2")

@RestController
@RequestMapping("/auth")
class AuthController {

    @PostMapping
    fun authenticate(
        @RequestBody authRequestDTO: AuthRequestDTO
    ): Boolean {
        return usersAllowed.contains(authRequestDTO.username) && passwordsAllowed.contains(authRequestDTO.password)
    }

    @PostMapping("/register")
    fun registerUser(
        @RequestBody authRequestDTO: AuthRequestDTO
    ): ResponseEntity<Any> {
        usersAllowed.add(authRequestDTO.username)
        passwordsAllowed.add(authRequestDTO.password)
        return ResponseEntity.status(HttpStatus.CREATED).build()
    }

    @GetMapping("/search", produces = [MediaType.TEXT_HTML_VALUE])
    fun search(@RequestParam query: String): ResponseEntity<String> {
        val body = "<html><body><h1>Resultado da busca por: $query</h1></body></html>"
        return ResponseEntity.ok(body)
    }

}