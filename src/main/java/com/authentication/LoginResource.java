package com.authentication;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import org.mindrot.jbcrypt.BCrypt;

import jakarta.resource.cci.ResultSet;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/login")
public class LoginResource {
    private String name;
    private String username;
    private String email;
    private String ced;
    private String password;

    // Constructor vacío
    public LoginResource() {
    }

    // Setters
    public void setName(String name) {
        this.name = name;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setCed(String ced) {
        this.ced = ced;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    // Método para registrar un nuevo usuario
    public boolean register() {
        boolean isRegistered = false;
        String url = "jdbc:mysql://localhost:3306/nombre_de_tu_base_de_datos";
        String dbUser = "tu_usuario";
        String dbPassword = "tu_contraseña";

        try {
            Connection connection = DriverManager.getConnection(url, dbUser, dbPassword);
            String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
            String sql = "INSERT INTO usuarios (nombre, ced, username, password, email) VALUES (?, ?, ?, ?, ?)";
            PreparedStatement statement = connection.prepareStatement(sql);
            statement.setString(1, name);
            statement.setString(2, ced);
            statement.setString(3, username);
            statement.setString(4, hashedPassword);
            statement.setString(5, email);

            int rowsInserted = statement.executeUpdate();
            if (rowsInserted > 0) {
                isRegistered = true;
            }

            statement.close();
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return isRegistered;
    }

    // Método para manejar la solicitud de registro de usuario
 // Método para manejar la solicitud de registro de usuario
 @POST
 @Path("/register")
 @Consumes(MediaType.APPLICATION_JSON)
 public Response registrarUsuario(User user) {
     setName(user.getName());
     setCed(user.getCed());
     setUsername(user.getUsername());
     setPassword(user.getPassword());
     setEmail(user.getEmail());

     if (register()) {
         return Response.ok("Registro exitoso").build();
     } else {
         return Response.status(Response.Status.BAD_REQUEST).entity("Registro fallido").build();
     }
 }

 // Método para manejar la solicitud de inicio de sesión
 @POST
 @Path("/login")
 @Consumes(MediaType.APPLICATION_JSON)
 public Response iniciarSesion(User user) {
    
     String url = "jdbc:mysql://localhost:3306/nombre_de_tu_base_de_datos";
     String dbUser = "tu_usuario";
     String dbPassword = "tu_contraseña";

     try {
         Connection connection = DriverManager.getConnection(url, dbUser, dbPassword);
         String sql = "SELECT password FROM usuarios WHERE username = ?";
         PreparedStatement statement = connection.prepareStatement(sql);
         statement.setString(1, user.getUsername());

         ResultSet resultSet = statement.executeQuery();
         if (resultSet.next()) {
             String storedHashedPassword = resultSet.getString("password");
             if (BCrypt.checkpw(user.getPassword(), storedHashedPassword)) {
                 return Response.ok("Inicio de sesión exitoso").build();
             } else {
                 return Response.status(Response.Status.UNAUTHORIZED).entity("Contraseña incorrecta").build();
             }
         } else {
             return Response.status(Response.Status.UNAUTHORIZED).entity("Usuario no encontrado").build();
         }
     } catch (Exception e) {
         e.printStackTrace();
         return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error en el servidor").build();
     }
 }
}
