package creditdirect.clientmicrocervice.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import creditdirect.clientmicrocervice.entities.Client;
import creditdirect.clientmicrocervice.entities.Particulier;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

public interface ClientService {
    public List<Client> getAllClients();
    public Client getClientById(Long id);
    public Client createClient(Client client);
    public Client updateClient(Long id, Client client);
    public Client getClientFromRemote(String email, String password ) throws JsonProcessingException;
    public void deleteClient(Long id);




    String login(String email, String password);


    Map<String, Object> loginWithClientInfo(String email, String password);

    Particulier subscribeParticulier(Particulier particulier);

    String generateRandomPassword();

    Client updateClientPassword(Long clientId, String newPassword);
    void activateClientByEmail(String email);


    String sendConfirmationEmail(String recipientEmail);

    ResponseEntity<String> updatePassword(Long id, String newPassword, String oldPassword);

    void resetPasswordByEmail(String email);


    Particulier updateParticulierinfo(Long id, Particulier updatedParticulier);
}
