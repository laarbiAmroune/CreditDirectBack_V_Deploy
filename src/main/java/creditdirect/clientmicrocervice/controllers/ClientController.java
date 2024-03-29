package creditdirect.clientmicrocervice.controllers;

import creditdirect.clientmicrocervice.entities.Client;
import creditdirect.clientmicrocervice.entities.Particulier;
import creditdirect.clientmicrocervice.services.ClientService;
import creditdirect.clientmicrocervice.services.EmailService;
import creditdirect.clientmicrocervice.services.EncryptionService;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/clients")
public class ClientController {

    private final ClientService clientService;
    private final EmailService emailService;

    private final EncryptionService encryptionService;

    ///////////////// get all client////////////////////////////

    @PreAuthorize("hasRole('admin')")
    @GetMapping
    public ResponseEntity<List<Client>> getAllClients() {
        List<Client> clients = clientService.getAllClients();
        return new ResponseEntity<>(clients, HttpStatus.OK);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Client> getClientById(@PathVariable("id") Long id) {
        Client client = clientService.getClientById(id);
        return client != null ? new ResponseEntity<>(client, HttpStatus.OK)
                : new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Client> updateClient(@PathVariable("id") Long id, @RequestBody Client client) {
        Client updatedClient = clientService.updateClient(id, client);
        return updatedClient != null ? new ResponseEntity<>(updatedClient, HttpStatus.OK)
                : new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    ///////////////////////// delete client///////////////////////
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteClient(@PathVariable("id") Long id) {
        clientService.deleteClient(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    //////////////////////// client login/////////////////////////
    @PostMapping("/login")
    public ResponseEntity<?> loginWithClientInfo(@RequestBody Map<String, String> credentials) {
        String email = credentials.get("email");
        String password = credentials.get("password");

        if (email == null || password == null) {
            return new ResponseEntity<>("Email or password missing", HttpStatus.BAD_REQUEST);
        }

        try {
            // Replace the following line with your actual authentication logic
            Map<String, Object> authenticationResult = clientService.loginWithClientInfo(email, password);

            if (authenticationResult.containsKey("error")) {
                // Authentication failed
                return new ResponseEntity<>(authenticationResult.get("error"), HttpStatus.UNAUTHORIZED);
            } else {
                // Authentication succeeded
                return ResponseEntity.ok(authenticationResult);
            }
        } catch (RuntimeException e) {
            log.error("Authentication failed: " + e.getMessage());
            return new ResponseEntity<>("Internal server error", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }



    ////////////////// inscription particulier///////////////////////////
    @PostMapping("/subscribe/particulier")
    public ResponseEntity<Object> subscribeParticulier(@RequestBody Particulier particulier) {
        try {
            Map<String, Object> response = clientService.subscribeParticulier(particulier);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (RuntimeException e) {
            // Handle the specific case where the email already exists
            if (e.getMessage().equals("Email already exists")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email already exists");
            }

            // Log the exception for debugging purposes
            log.error("Error during particulier subscription", e);

            // Handle other runtime exceptions if necessary
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
        } catch (Exception e) {
            // Log the exception for debugging purposes
            log.error("Unexpected error during particulier subscription", e);

            // Handle other exceptions if necessary
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
        }
    }

    /////////////////// updaate client password/////////////////////////
    @PutMapping("/addpassword")
    public ResponseEntity<String> updateClientPassword(@RequestParam Long id,
            @RequestBody Map<String, String> requestBody) {
        String password = requestBody.get("password");

        if (id == null || password == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid request format");
        }

        System.out.println("Received request to update password for Client ID: " + id);

        Client updatedClient = clientService.updateClientPassword(id, password);

        if (updatedClient != null) {
            return ResponseEntity.ok("Password updated successfully for Client ID: " + id);
        } else {
            System.out.println("Client with ID " + id + " not found");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Client with ID " + id + " not found");
        }
    }
    /*
     * @GetMapping("/activate")
     * public ResponseEntity<String> activateClientByEmail(@RequestParam("email")
     * String email) {
     * clientService.activateClientByEmail(email);
     * 
     * String htmlResponse = "<html>"
     * + "<head><title>Activation Successful</title></head>"
     * + "<body>"
     * + "<h1>Client Activation</h1>"
     * + "<p>Client with email " + email + " has been activated.</p>"
     * + "</body>"
     * + "</html>";
     * 
     * return ResponseEntity.status(HttpStatus.OK).body(htmlResponse);
     * }
     */

    ///////////////////////// activer compte client via
    ///////////////////////// email////////////////////////////
    @GetMapping("/activate")
    public ResponseEntity<String> activateClientByEmail(@RequestParam("email") String email) {
        try {
            // clientService.activateClientByEmail(email);

            System.out.print("decrypteemailanvat proces" + email);
            String decrypteemail = encryptionService.decrypt(email);
            System.out.print("decrypteemail" + decrypteemail);

            clientService.activateClientByEmail(decrypteemail);

            String htmlResponse = "<!DOCTYPE html>\n" +
                    "<html>\n" +
                    "<head>\n" +
                    "  <link href=\"https://fonts.googleapis.com/css?family=Nunito+Sans:400,400i,700,900&display=swap\" rel=\"stylesheet\">\n"
                    +
                    "</head>\n" +
                    "<style>\n" +
                    "  body {\n" +
                    "    text-align: center;\n" +
                    "    padding: 40px 0;\n" +
                    "    background: #EBF0F5;\n" +
                    "  }\n" +
                    "\n" +
                    "  h1 {\n" +
                    "    color: #88B04B;\n" +
                    "    font-family: \"Nunito Sans\", \"Helvetica Neue\", sans-serif;\n" +
                    "    font-weight: 900;\n" +
                    "    font-size: 40px;\n" +
                    "    margin-bottom: 10px;\n" +
                    "  }\n" +
                    "\n" +
                    "  p {\n" +
                    "    color: #404F5E;\n" +
                    "    font-family: \"Nunito Sans\", \"Helvetica Neue\", sans-serif;\n" +
                    "    font-size: 20px;\n" +
                    "    margin: 0;\n" +
                    "  }\n" +
                    "\n" +
                    "  i {\n" +
                    "    color: #9ABC66;\n" +
                    "    font-size: 100px;\n" +
                    "    line-height: 200px;\n" +
                    "    margin-left: -15px;\n" +
                    "  }\n" +
                    "\n" +
                    "  .card {\n" +
                    "    background: white;\n" +
                    "    padding: 60px;\n" +
                    "    border-radius: 4px;\n" +
                    "    box-shadow: 0 2px 3px #C8D0D8;\n" +
                    "    display: inline-block;\n" +
                    "    margin: 0 auto;\n" +
                    "  }\n" +
                    "</style>\n" +
                    "\n" +
                    "<body>\n" +
                    "  <div class=\"card\">\n" +
                    "    <div style=\"border-radius:200px; height:200px; width:200px; background: #F8FAF5; margin:0 auto;\">\n"
                    +
                    "      <i class=\"checkmark\">✓</i>\n" +
                    "    </div>\n" +
                    "    <h1>Succès</h1>\n" +
                    "    <p>Votre compte a été activé avec succès !</p>\n" +
                    "  </div>\n" +
                    "</body>\n" +
                    "</html>";


            return ResponseEntity.status(HttpStatus.OK).body(htmlResponse);
        } catch (Exception e) {
            // Handle activation failure or other exceptions
            String errorHtmlResponse = "<!DOCTYPE html>\n" +
                    "<html>\n" +
                    "<head>\n" +
                    "  <link href=\"https://fonts.googleapis.com/css?family=Nunito+Sans:400,400i,700,900&display=swap\" rel=\"stylesheet\">\n"
                    +
                    "</head>\n" +
                    "<style>\n" +
                    "  body {\n" +
                    "    text-align: center;\n" +
                    "    padding: 40px 0;\n" +
                    "    background: #EBF0F5;\n" +
                    "  }\n" +
                    "\n" +
                    "  h1 {\n" +
                    "    color: #FF0000;\n" +
                    "    font-family: \"Nunito Sans\", \"Helvetica Neue\", sans-serif;\n" +
                    "    font-weight: 900;\n" +
                    "    font-size: 40px;\n" +
                    "    margin-bottom: 10px;\n" +
                    "  }\n" +
                    "\n" +
                    "  p {\n" +
                    "    color: #404F5E;\n" +
                    "    font-family: \"Nunito Sans\", \"Helvetica Neue\", sans-serif;\n" +
                    "    font-size: 20px;\n" +
                    "    margin: 0;\n" +
                    "  }\n" +
                    "\n" +
                    "  .card {\n" +
                    "    background: white;\n" +
                    "    padding: 60px;\n" +
                    "    border-radius: 4px;\n" +
                    "    box-shadow: 0 2px 3px #C8D0D8;\n" +
                    "    display: inline-block;\n" +
                    "    margin: 0 auto;\n" +
                    "  }\n" +
                    "</style>\n" +
                    "\n" +
                    "<body>\n" +
                    "  <div class=\"card\">\n" +
                    "    <h1>Erreur</h1>\n" +
                    "    <p>Le serveur a rencontré un problème. Veuillez réessayer plus tard.</p>\n" +

                    "  </div>\n" +
                    "</body>\n" +
                    "</html>";


            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorHtmlResponse);
        }
    }

    /////////////// envoyer un email de confirmation///////////////////////

    @PostMapping("/send-confirmation-email")
    public String sendConfirmationEmail(@RequestBody Map<String, String> requestBody) {
        String recipientEmail = requestBody.get("recipientEmail");
        return clientService.sendConfirmationEmail(recipientEmail);
    }



    @PutMapping("/{id}/reset-password")
    public ResponseEntity<String> updatePassword(@PathVariable Long id, @RequestBody Map<String, String> requestBody) {
        String oldPassword = requestBody.get("oldPassword");
        String newPassword = requestBody.get("newPassword");

        if (id == null || oldPassword == null || newPassword == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Format de requête invalide");
        }

        System.out.println("Requête reçue pour mettre à jour le mot de passe du client ID : " + id + newPassword + oldPassword);

        ResponseEntity<String> updateResponse = clientService.updatePassword(id, newPassword, oldPassword);

        return updateResponse;
    }

    @PutMapping("/reset-password")
    public ResponseEntity<String> resetPasswordByEmail(@RequestBody String email) {
        try {
            clientService.resetPasswordByEmail(email);
            return ResponseEntity.ok("Un e-mail de réinitialisation de mot de passe a été envoyé à l'adresse : " + email);
        } catch (EntityNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
        }
    }


    @PutMapping("/updateparticulier/{id}")
    public ResponseEntity<Particulier> updateParticulierinfo(@PathVariable Long id, @RequestBody Particulier updatedParticulier) {
        Particulier updatedEntity =clientService.updateParticulierinfo(id, updatedParticulier);
        return new ResponseEntity<>(updatedEntity, HttpStatus.OK);
    }

}
