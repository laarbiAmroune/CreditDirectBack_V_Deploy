package creditdirect.clientmicrocervice.services;
import java.lang.reflect.Field;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import creditdirect.clientmicrocervice.entities.Client;
import creditdirect.clientmicrocervice.entities.Commune;
import creditdirect.clientmicrocervice.entities.Particulier;
import creditdirect.clientmicrocervice.repositories.ClientRepository;
import creditdirect.clientmicrocervice.repositories.CommuneRepository;
import creditdirect.clientmicrocervice.repositories.ParticulierRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@RequiredArgsConstructor
@Service
public class ClientServiceImpl implements ClientService {

    @Builder
    @Data
    static class RequestBody {
        private String email;
        private String password;
    }

    private static final String SECRET_KEY = "ThisIsASecureSecretKeyWithAtLeast256BitsLength123456789012345678901234567890";
    // Replace with your actual secret key
    private static final long EXPIRATION_TIME = 864_000_000; // 10 days in milliseconds
    private static final Logger logger = LoggerFactory.getLogger(ClientServiceImpl.class);

    private final ClientRepository clientRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Override
    public List<Client> getAllClients() {
        return clientRepository.findAll();
    }

    @Override
    public Client getClientById(Long id) {
        return clientRepository.findById(id).orElse(null);
    }

    @Override
    public Client createClient(Client client) {
        return clientRepository.save(client);
    }

    @Override
    public Client updateClient(Long id, Client client) {
        if (clientRepository.existsById(id)) {
            client.setId(id);
            return clientRepository.save(client);
        }
        return null; // Or handle as per requirement
    }

    @Override
    public Client getClientFromRemote(String _email, String _password) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        RestTemplate template = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity httpEntity = new HttpEntity<>(
                RequestBody
                        .builder()
                        .email(_email)
                        .password(_password)
                        .build(),
                headers);
        ResponseEntity<String> response = template.postForEntity(
                // configService.getConfigs().get("centrale-url") + baseAPi
                "http://localhost:8001/api/v1/client/auth", httpEntity, String.class);

        if (response.getStatusCode().is2xxSuccessful()) {
            String responseBody = response.getBody().toString();
            // log.info(responseBody);
            Map<String, Object> data = mapper.readValue(responseBody, Map.class);
            Client client = Client.builder()
                    .email(_email)
                    .password(passwordEncoder.encode(_password))
                    .build();
            Particulier particulier = new Particulier();

            particulier.setAdresse((String) data.get("adress"));
            particulier.setCivilite((String) data.get("civilite"));
            particulier.setNationalite((String) data.get("nationalite"));
            particulier.setNom((String) data.get("nom"));
            particulier.setPrenom((String) data.get("prenom"));
            particulier.setCodePostal((String) data.get("codePostal"));
            particulier.setTelephone((String) data.get("telephone"));
            particulier.setVille((String) data.get("ville"));
            particulier.setPassword(passwordEncoder.encode(_password));

            // particulier.setCommune(communeRepository.findByCodePostal((String)data.get("codePostal")));

            particulierRepository.save(particulier);
            clientRepository.save(client);
        }

        return null;
    }

    @Override
    public void deleteClient(Long id) {
        clientRepository.deleteById(id);
    }

    @Override
    public String login(String email, String password) {
        Client client = clientRepository.findByEmail(email);
        if (client != null && passwordEncoder.matches(password, client.getPassword())) {

            return generateToken(client);
        } else {
            return "Authentication failed";
        }
    }

    @Override
    public Map<String, Object> loginWithClientInfo(String email, String password) {
        try {
            Client client = clientRepository.findByEmail(email);
            Map<String, Object> response = new HashMap<>();

            if (client != null && passwordEncoder.matches(password, client.getPassword())) {

                if (client.isActivated()) {
                    String token = generateToken(client);
                    String clientType = getClientType(client);

                    response.put("client", client); // Adding client information to the response
                    response.put("role", clientType); // Adding client type to the response
                    response.put("token", token);
                } else {
                    response.put("error", "Account is not activated");
                }
            } else {
                response.put("error", "Invalid credentials");
            }

            return response;
        } catch (Exception e) {
            // Handle other exceptions if necessary
            throw new RuntimeException("Internal server error", e);
        }
    }

    private String getClientType(Client client) {
        if (client instanceof Particulier) {
            return "Particulier";
        } else {
            return "Client";
        }
    }

    private String generateToken(Client client) {
        try {

            String clientType = getClientType(client);
            System.out.println("Logged in as " + clientType);
            JWTClaimsSet claims = new JWTClaimsSet.Builder()

                    .subject(client.getEmail())
                    .claim("role", clientType.toString())
                    .claim("id", client.getId().toString()) // Include ID in the claim
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                    .build();


            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);

            MACSigner signer = new MACSigner(SECRET_KEY);
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (JOSEException e) {
            logger.error("Error generating JWT token for email: {}", client, e);
            // Add additional handling here if necessary
            return null;
        }
    }

    @Autowired
    private ParticulierRepository particulierRepository;
    /*
     * @Override
     * public Particulier subscribeParticulier(Particulier particulier) {
     * // Add any business logic or validation here before saving
     * return particulierRepository.save(particulier);
     * }
     */

    /*
     * @Override
     * public Particulier subscribeParticulier(Particulier particulier) {
     * 
     * String generatedPassword = generateRandomPassword();
     * System.out.println("generated passeword: " + generatedPassword);
     * String hashedPassword = passwordEncoder.encode(generatedPassword);
     * particulier.setPassword(hashedPassword );
     * Particulier subscribedParticulier = particulierRepository.save(particulier);
     * emailService.sendConfirmationEmail(subscribedParticulier.getEmail());
     * 
     * // Retrieve Commune based on postal code
     * String postalCode = particulier.getCodePostal(); // Assuming you have a
     * method to get postal code from Particulier
     * Commune commune = communeRepository.findByCodePostal(postalCode);
     * 
     * if (commune != null) {
     * subscribedParticulier.setCommune(commune); // Associate Particulier with
     * Commune
     * return particulierRepository.save(subscribedParticulier); // Save and return
     * the updated Particulier
     * } else {
     * // Handle scenario when Commune is not found for the provided postal code
     * return null;
     * }
     * 
     * return subscribedParticulier;
     * }
     */

    @Override
    public Particulier subscribeParticulier(Particulier particulier) {
        try {
            // Check if the email already exists
            if (clientRepository.existsByEmail(particulier.getEmail())) {
                System.out.println("Email already exists: " + particulier.getEmail());
                throw new RuntimeException("Email already exists");
            }

            String generatedPassword = generateRandomPassword();
            System.out.println("Generated password: " + generatedPassword);

            String hashedPassword = passwordEncoder.encode(generatedPassword);
            particulier.setPassword(hashedPassword);

            // Save the Particulier first
            Particulier subscribedParticulier = particulierRepository.save(particulier);
            emailService.sendConfirmationEmail(subscribedParticulier.getEmail(), generatedPassword);
            System.out.println("Sending confirmation email to: " + subscribedParticulier.getEmail());

            String postalCode = particulier.getCodePostal(); // Assuming you have a method to get postal code from
                                                             // Particulier
            Commune commune = communeRepository.findByCodePostal(postalCode);
            System.out.println("postalCode postalCode: " + postalCode);

            if (commune != null) {
                subscribedParticulier.setCommune(commune); // Associate Particulier with Commune
                particulierRepository.save(subscribedParticulier);
                return subscribedParticulier; // Save and return the updated Particulier
            } else {
                // Handle scenario when Commune is not found for the provided postal code
                return null;
            }
        } catch (RuntimeException e) {
            throw e; // Re-throw the exception to be handled globally or customize the response here
        } catch (Exception e) {
            // Handle other exceptions if necessary
            throw new RuntimeException("Internal server error", e);
        }
    }

    /////////////// generate password ////////////////////////////

    @Override
    public String generateRandomPassword() {

        String uuid = UUID.randomUUID().toString().replace("-", "");

        return uuid.substring(0, 8);
    }

    @Autowired
    private CommuneRepository communeRepository;

    @Override
    public Client updateClientPassword(Long clientId, String password) {
        Optional<Client> optionalClient = clientRepository.findById(clientId);

        if (optionalClient.isPresent()) {
            Client client = optionalClient.get();
            String hashedPassword = passwordEncoder.encode(password);
            client.setPassword(hashedPassword);
            return clientRepository.save(client);
        } else {
            // Handle case where client with provided ID doesn't exist
            // You can throw an exception or return null/throw a custom exception
            return null;
        }
    }

    @Override
    public void activateClientByEmail(String email) {
        Client client = clientRepository.findByEmail(email);
        if (client == null) {
            throw new EntityNotFoundException("Client not found with email: " + email);
        }

        client.setActivated(true);
        clientRepository.save(client);
    }

    @Override
    public String sendConfirmationEmail(String recipientEmail) {
        // Retrieve existing Client entity from the database
        System.out.print(recipientEmail + "recipientEmail");
        Client existingClient = clientRepository.findByEmail(recipientEmail);

        if (existingClient == null) {
            // Handle the case where the entity does not exist
            return "Client not found for email: " + recipientEmail;
        }

        // Generate a random password
        String generatedPassword = generateRandomPassword();
        System.out.println("Generated password: " + generatedPassword);

        // Hash the generated password
        String hashedPassword = passwordEncoder.encode(generatedPassword);

        // Update fields in the existing entity
        existingClient.setPassword(hashedPassword);

        // Save the updated entity
        Client subscribedClient = clientRepository.save(existingClient);

        // Send confirmation email
        emailService.sendConfirmationEmail(subscribedClient.getEmail(), generatedPassword);

        return "Confirmation email sent to " + recipientEmail;
    }

    @Override
    public ResponseEntity<String> updatePassword(Long clientId, String newPassword, String oldPassword) {
        Optional<Client> optionalClient = clientRepository.findById(clientId);

        if (optionalClient.isPresent()) {
            Client client = optionalClient.get();
            String hashedNewPassword = passwordEncoder.encode(newPassword);

            if (passwordEncoder.matches(oldPassword, client.getPassword())){

                client.setPassword(hashedNewPassword);
                clientRepository.save(client);
                return ResponseEntity.ok("Mot de passe mis à jour avec succès");

            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Ancien mot de passe incorrect");
            }
        } else {
            // Handle case where client with provided ID doesn't exist
            // You can throw an exception or return an appropriate ResponseEntity
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Client introuvable avec l'ID fourni");
        }
    }


    @Override
    public void resetPasswordByEmail(String email) {
        Client client = clientRepository.findByEmail(email);

        if (client != null) {
            // Générer un nouveau mot de passe
            String newPassword = generateRandomPassword();
            String hashedNewPassword = passwordEncoder.encode(newPassword);
            client.setPassword(hashedNewPassword);

            // Sauvegarder le client avec le nouveau mot de passe
            clientRepository.save(client);

            // Envoyer un e-mail avec le nouveau mot de passe
            emailService.sendPasswordResetEmail(client.getEmail(), newPassword, client.getEmail());
        } else {
            throw new EntityNotFoundException("Client non trouvé avec l'e-mail : " + email);
        }
    }
    @Override
    @Transactional
    public Particulier updateParticulierinfo(Long id, Particulier updatedParticulier) {
        Particulier existingParticulier = particulierRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Particulier not found with id: " + id));

        Client existingClient = clientRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Client not found with id: " + id));

        // Update only non-null fields from the updatedParticulier
        updateNonNullFields(existingParticulier, updatedParticulier);

        // Update email field using clientRepository
        if (updatedParticulier.getEmail() != null) {
            existingClient.setEmail(updatedParticulier.getEmail());
            clientRepository.save(existingClient);
        }

        // Save the updated entities
        particulierRepository.save(existingParticulier);

        return existingParticulier;
    }

    private void updateNonNullFields(Object target, Object source) {
        Class<?> targetClass = target.getClass();
        Field[] fields = targetClass.getDeclaredFields();

        for (Field field : fields) {
            try {
                field.setAccessible(true);
                Object sourceValue = field.get(source);
                if (sourceValue != null) {
                    field.set(target, sourceValue);
                }
            } catch (IllegalAccessException e) {
                // Handle the exception based on your application's requirements
                throw new RuntimeException("Error updating field: " + field.getName(), e);
            }
        }
    }


    ///////////////////////////other option
    @Override
    public Particulier updateParticulierInformation(Long clientId, Particulier updatedParticulier) {
        // Retrieve the Particulier entity using the client ID
        Particulier existingParticulier = particulierRepository.findById(clientId)
                .orElseThrow(() -> new RuntimeException("Particulier not found with id: " + clientId));

        Client existingClient = clientRepository.findById(clientId)
                .orElseThrow(() -> new RuntimeException("Client not found with id: " + clientId));

        // Check if the retrieved entity is indeed a Particulier
        if (!(existingParticulier instanceof Particulier)) {
            throw new RuntimeException("Client with id " + clientId + " is not a Particulier");
        }

        // Cast it to Particulier
        Particulier particulier = (Particulier) existingParticulier;

        Client client = (Client) existingClient;

        // Update only specific fields
        particulier.setNom(updatedParticulier.getNom());
        particulier.setPrenom(updatedParticulier.getPrenom());
        client.setEmail(updatedParticulier.getEmail());
        particulier.setTelephone(updatedParticulier.getTelephone());
        particulier.setAdresse(updatedParticulier.getAdresse());
        particulier.setWilaya(updatedParticulier.getWilaya());
        particulier.setCommune(updatedParticulier.getCommune());

        // Save and return the updated particulier
        particulierRepository.save(particulier);
        clientRepository.save(client);

        return particulier;
    }

}
