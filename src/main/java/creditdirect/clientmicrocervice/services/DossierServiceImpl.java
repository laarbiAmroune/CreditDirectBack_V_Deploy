package creditdirect.clientmicrocervice.services;


import creditdirect.clientmicrocervice.config.FileStorageProperties;
import creditdirect.clientmicrocervice.entities.*;
import creditdirect.clientmicrocervice.repositories.*;
import jakarta.persistence.*;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;


@Service
public class DossierServiceImpl implements DossierService {

    private final DossierRepository dossierRepository;
    private final ClientRepository clientRepository;
    private final FileStorageService fileStorageService;

    private final ParticulierRepository particulierRepository;
    private final TypeCreditRepository typeCreditRepository;
    private final TypeFinancementRepository typeFinancementRepository;
    private final AgenceRepository agenceRepository;
    private final CompteRepository compteRepository;

    private final String uploadDir; // Injecting the upload directory
    private final EntityManager entityManager;

    private final AgenceCommuneService agenceService;

    @Autowired
    public DossierServiceImpl(DossierRepository dossierRepository, ClientRepository clientRepository,
                              FileStorageService fileStorageService, TypeCreditRepository typeCreditRepository,
                              TypeFinancementRepository typeFinancementRepository,FileStorageProperties fileStorageProperties,
                              CompteRepository compteRepository,ParticulierRepository particulierRepository, EntityManager entityManager,
                              AgenceRepository agenceRepository, AgenceCommuneService agenceService) {
        this.dossierRepository = dossierRepository;
        this.clientRepository = clientRepository;
        this.fileStorageService = fileStorageService;
        this.typeCreditRepository = typeCreditRepository;
        this.compteRepository = compteRepository;
        this.typeFinancementRepository = typeFinancementRepository;
        this.agenceRepository = agenceRepository;
        this.particulierRepository =particulierRepository;
        this.entityManager = entityManager;
        this.agenceService = agenceService;


        this.uploadDir = fileStorageProperties.getUploadDir();
        initializeUploadDir();

    }


    @Override
    @Transactional
    public Dossier addDossier(Dossier dossier) {
        Long clientId = dossier.getClient().getId();

        System.out.println("ajoute du dossier");
        System.out.println("Client ID: " + clientId);

        Client client = clientRepository.findById(clientId)
                .orElseThrow(() -> new RuntimeException("Client not found"));
        dossier.setClient(client);
   return dossierRepository.save(dossier);
    }


    @Override
    public Dossier affectiondossieragence(Long dossierId) {
        Optional<Dossier> optionalDossier = dossierRepository.findById(dossierId);
        Dossier dossier = optionalDossier.orElseThrow(() -> new RuntimeException("Dossier not found"));

        Long clientId = dossier.getClient().getId();

        Client client = clientRepository.findById(clientId)
                .orElseThrow(() -> new RuntimeException("Client not found"));
        dossier.setClient(client);

        if (client instanceof Particulier) {
            Particulier particulier = (Particulier) client;
            System.out.println("particulier ID: " + particulier);
            // Assuming particulierId is retrieved from somewhere, it's not defined in the given code
            Particulier foundParticulier = particulierRepository.findById(particulier.getId()).orElse(null);

            if (foundParticulier != null) {
                Commune commune = foundParticulier.getCommune();

                if (commune != null) {
                    List<Agence> agences = findAgencesByCommuneId(commune.getId());
                    System.out.println("commune ID: " + commune.getId());
                    System.out.println("agences ID: " + agences);

                    if (agences.size() == 1) {
                        System.out.println("Cette commune appartient à une seule agence");
                        Agence singleAgence = agences.get(0);
                        Long agenceId = singleAgence.getId();
                        System.out.println("agenceId"+agenceId);
                        if (agenceId != null) {
                            dossier.setAssignedagence(singleAgence);
                        }

                        return dossierRepository.save(dossier);
                    } else if (agences.size() > 1) {
                        System.out.println("Cette commune appartient à plusieurs agences");
                        Agence firstAgence = agences.get(0);
                        System.out.println("firstAgence"+firstAgence);
                        DirectionRegionale directionRegionale = firstAgence.getDirectionRegionale();

                        if (directionRegionale != null) {
                            Long directionRegionaleId = directionRegionale.getId();
                            System.out.println("directionRegionaleId"+directionRegionaleId);
                            dossier.setAssigneddirectionregionnale(directionRegionale);
                        }

                        return dossierRepository.save(dossier);
                    }
                }
            }
        }

        return dossierRepository.save(dossier);
    }



    public Dossier updateFilesForDossier(Long dossierId, MultipartFile[] files) {
        Dossier dossier = dossierRepository.findById(dossierId)
                .orElseThrow(() -> new RuntimeException("Dossier not found with id: " + dossierId));

        List<AttachedFile> attachedFiles = dossier.getAttachedFiles();

        // Store the new files and retrieve AttachedFile objects
        List<AttachedFile> newAttachedFiles = fileStorageService.storeFilesForDossier(files, dossierId);

        // Add the new AttachedFile objects to the existing list
        if (attachedFiles == null) {
            attachedFiles = new ArrayList<>();
        }
        attachedFiles.addAll(newAttachedFiles);

        // Update the attached files list in the Dossier entity
        dossier.setAttachedFiles(attachedFiles);

        return dossierRepository.save(dossier);
    }

    @Override
    public Long getSingleAgenceIdByParticulierId(Long particulierId) {
        Particulier particulier = particulierRepository.findById(particulierId).orElse(null);

        if (particulier != null) {
            Commune commune = particulier.getCommune();

            if (commune != null) {
                List<Agence> agences = findAgencesByCommuneId(commune.getId());

                if (agences.size() == 1) {
                    System.out.println("cette commune aprtient a une seul agence");
                    Agence singleAgence = agences.get(0);
                    return singleAgence.getId();
                }
            }
        }

        return null;
    }

    ///////////////////queries
    @Override
    public List<Agence> findAgencesByCommuneId(Long communeId) {
        String jpql = "SELECT a FROM Agence a JOIN a.communes c WHERE c.id = :communeId";
        TypedQuery<Agence> query = entityManager.createQuery(jpql, Agence.class);
        query.setParameter("communeId", communeId);
        return query.getResultList();
    }




    @Override

    public Long findAgenceRegionaleIdByParticulierId(Long idParticulier) {

        System.out.println("idParticulier ID: " + idParticulier);

        String jpql = "SELECT a.id FROM Particulier p " +
                "JOIN p.commune c " +
                "JOIN c.agences a " +

                "WHERE p.id = :idParticulier "
                ; // Ordonne par l'ID de l'Agence pour obtenir la première


        Query query = entityManager.createQuery(jpql);
        query.setParameter("idParticulier", idParticulier);

        try {
            return (Long) query.getSingleResult();

        } catch (Exception e) {
            return null; // or handle the exception as needed
        }
    }





    ///////////////////////////////////////////////////

    private void initializeUploadDir() {
        Path path = Paths.get(uploadDir);
        if (!Files.exists(path)) {
            try {
                Files.createDirectories(path);
            } catch (IOException e) {
                e.printStackTrace(); // Handle the exception properly
            }
        }
    }
    @Override
    public List<Dossier> getAllDossiers() {
        return dossierRepository.findAll();
    }


    @Override
    public Dossier getDossierById(Long id) {
        return dossierRepository.findById(id).orElse(null);
    }

    @Override
    public List<Dossier> getDossiersByClientId(Long clientId) {
        // Assuming you have a method in DossierRepository to find dossiers by client ID
        return dossierRepository.findByClientId(clientId);
    }
    @Override
    public Dossier assignDossierToCourtier(Long dossierId, Long courtierId) {
        try {
            Dossier dossier = dossierRepository.findById(dossierId)
                    .orElseThrow(() -> new EntityNotFoundException("Dossier not found with id: " + dossierId));

            Compte courtier = compteRepository.findById(courtierId)
                    .orElseThrow(() -> new EntityNotFoundException("Courtier not found with id: " + courtierId));

            dossier.setAssignedCourtier(courtier);
            dossier.setStatus(DossierStatus.TRAITEMENT_ENCOURS); // Assuming a new assignment resets status
            dossierRepository.save(dossier);
            Long agenceId = dossier.getAssignedagence().getId();
            if (agenceId == null) {
                throw new EntityNotFoundException("agence not found for this dossiers");
            }

            Compte directeur = findDirecteurByAgenceId(agenceId);
            if (directeur == null) {
                throw new EntityNotFoundException("Directeur not found for agenceId: " + agenceId);
            }
            dossier.setDirecteurAgence(directeur);

            return dossierRepository.save(dossier);
        } catch (EntityNotFoundException e) {
            // Rethrow EntityNotFoundException to be caught by the controller
            throw e;
        } catch (IllegalStateException e) {
            // Rethrow IllegalStateException to be caught by the controller
            throw e;
        } catch (RuntimeException e) {
            // Rethrow RuntimeException to be caught by the controller
            throw e;
        } catch (Exception e) {
            // Handle other exceptions if necessary
            throw new RuntimeException("An unexpected error occurred during dossier assignment.", e);
        }
    }


    public Compte findDirecteurByAgenceId(Long agenceId) {
        String jpql = "SELECT c FROM Compte c WHERE c.agenceId = :agenceId AND c.role = :role";
        TypedQuery<Compte> query = entityManager.createQuery(jpql, Compte.class);
        query.setParameter("agenceId", agenceId);
        query.setParameter("role", RoleType.directeur);

        try {
            return query.getSingleResult();
        } catch (NoResultException e) {
            // Handle the case where no result is found (return null or throw an EntityNotFoundException)
            throw new EntityNotFoundException("Directeur not found for agenceId: " + agenceId);
        } catch (NonUniqueResultException e) {
            // Handle the case where more than one result is found (throw an exception or handle accordingly)
            throw new IllegalStateException("More than one directeur found for agenceId: " + agenceId);
        } catch (Exception e) {
            // Handle other exceptions if necessary
            throw new RuntimeException("An error occurred while finding directeur.", e);
        }
    }
    // courtier avoir les dossiers non traiter
    @Override
    public List<Dossier> getDossiersForCourtier(Long courtierId) {
        return dossierRepository.findAllByAssignedagenceIdAndStatus(courtierId, DossierStatus.NON_TRAITEE);
    }


    @Override
    public List<Dossier> getDossiersencoursForCourtier(Long courtierId) {
        return dossierRepository.findAllByAssignedCourtier_IdAndStatus(courtierId, DossierStatus.TRAITEMENT_ENCOURS);
    }




    // dossiers traiter par le courtier
    @Override
    public List<Dossier> getTraiteeDossiersByCourtier(Long courtierId) {
        return dossierRepository.findAllByAssignedCourtier_IdAndStatus(courtierId, DossierStatus.TRAITEE);
    }



    @Override
    public void updateDossierStatusToTraitee(Long dossierId) {
        Optional<Dossier> dossierOptional = dossierRepository.findById(dossierId);
        dossierOptional.ifPresent(dossier -> {
            dossier.setStatus(DossierStatus.TRAITEE);
            dossierRepository.save(dossier);
        });
    }
    @Override
    public void updateDossiersStatusToTraitee(List<Long> dossierIds) {
        List<Dossier> dossiersToUpdate = dossierRepository.findAllById(dossierIds);
        dossiersToUpdate.forEach(dossier -> dossier.setStatus(DossierStatus.TRAITEE));
        dossierRepository.saveAll(dossiersToUpdate);
    }
    @Override
    // New method to update status to "ACCEPTER"
    public void updateDossiersStatusToAccepter(List<Long> dossierIds) {
        List<Dossier> dossiersToUpdate = dossierRepository.findAllById(dossierIds);
        dossiersToUpdate.forEach(dossier -> dossier.setStatus(DossierStatus.ACCEPTER));
        dossierRepository.saveAll(dossiersToUpdate);
    }
    @Override
    // New method to update status to "REFUSER"
    public void updateDossiersStatusToRefuser(List<Long> dossierIds) {
        List<Dossier> dossiersToUpdate = dossierRepository.findAllById(dossierIds);
        dossiersToUpdate.forEach(dossier -> dossier.setStatus(DossierStatus.REFUSER));
        dossierRepository.saveAll(dossiersToUpdate);
    }
    @Override
    // New method to update status to "RENVOYER"
    public void updateDossiersStatusToRenvoyer(List<Long> dossierIds) {
        List<Dossier> dossiersToUpdate = dossierRepository.findAllById(dossierIds);
        dossiersToUpdate.forEach(dossier -> dossier.setStatus(DossierStatus.RENVOYER));
        dossierRepository.saveAll(dossiersToUpdate);
    }

////////////////////////////////////////////////
    //////////////////////////

    @Autowired
    private CommentaireRepository commentaireRepository;



    @Override
    public void updateStatusToRenvoyer(Long idDossier, Long idCompte, String comment) {
        Dossier dossier = dossierRepository.findById(idDossier).orElse(null);
        Compte compte = compteRepository.findById(idCompte).orElseThrow(() -> new RuntimeException("Compte not found with id: " + idCompte));

        if (dossier != null) {
            dossier.setStatus(DossierStatus.RENVOYER);

            // Save the updated dossier with the new status
            dossierRepository.save(dossier);

            // Check if comment is provided and save it to Commentaire entity
            if (comment != null && !comment.isEmpty()) {
                Commentaire commentaire = new Commentaire();
                commentaire.setDossier(dossier);
                // Set only the content of the comment
                commentaire.setComment(comment);
                commentaire.setStatus(dossier.getStatus());
                commentaire.setCommentDate(LocalDateTime.now());

                // Set the associated Compte
                commentaire.setCompte(compte);

                // Save the comment
                commentaireRepository.save(commentaire);
            }
        } else {
            throw new RuntimeException("Dossier not found with id: " + idDossier);
        }




    }




    @Override

    public List<Dossier> getAcceptedAndRejectedDossiersByCourtier(Long courtierId) {
        List<DossierStatus> desiredStatuses = Arrays.asList(
                DossierStatus.ACCEPTER,
                DossierStatus.REFUSER,
                DossierStatus.RENVOYER,
                DossierStatus.TRAITEMENT_ENCOURS,
                DossierStatus.TRAITEE,
                DossierStatus.NON_TRAITEE
        );

        return dossierRepository.findByAssignedCourtierIdAndStatusIn(courtierId, desiredStatuses);
    }


    ///////////////////////delete file by file name and id dossier/////////////////
    public boolean deleteFileByDossierIdAndFileName(Long dossierId, String fileName) {
        Optional<Dossier> optionalDossier = dossierRepository.findById(dossierId);

        if (optionalDossier.isPresent()) {
            Dossier dossier = optionalDossier.get();
            List<AttachedFile> attachedFiles = dossier.getAttachedFiles();
            AttachedFile fileToDelete = null;

            for (AttachedFile file : attachedFiles) {
                if (file.getFileName().equals(fileName)) {
                    fileToDelete = file;
                    break;
                }
            }

            if (fileToDelete != null) {
                attachedFiles.remove(fileToDelete);
                dossierRepository.save(dossier);
                // Optionally, perform other operations like deleting the file from storage
                return true; // File deleted successfully
            } else {
                // Handle case: File not found in the dossier
                return false; // File not found in dossier's attached files
            }
        } else {
            // Handle case: Dossier not found
            return false; // Dossier not found with the given ID
        }
    }


    /////////////////////////////////





    @Override
    public List<Dossier> getAllDossiersByAgence(Long assignedAgenceId) {
        Agence assignedAgence = agenceService.getAgenceById(assignedAgenceId); // Fetch Agence by ID

        if (assignedAgence == null) {
            // Handle the case where the Agence with the given ID is not found
            return Collections.emptyList(); // Or throw an exception as needed
        }

        return dossierRepository.findAllByAssignedagence(assignedAgence);
    }
    private static final String BASE_UPLOAD_DIR = "C:/Users/user/lastbanklend/CreditDirectbackend/ClientMicrocervice/src/main/resources/uploaded-files/";

    @Override
    public byte[] downloadFileByDossierIdAndFileName(Long dossierId, String fileName) throws IOException {
        Path filePath = Paths.get(BASE_UPLOAD_DIR, String.valueOf(dossierId), fileName);
        return Files.readAllBytes(filePath);
    }


    @Override
    @Transactional
    public void setDossiersStatusToAccepter(List<Long> dossierIds, String comment, Long idCompte) {
        for (Long idDossier : dossierIds) {
            try {
                // Retrieve the dossier by its ID
                Dossier dossier = dossierRepository.findById(idDossier)
                        .orElseThrow(() -> new RuntimeException("Dossier not found with ID: " + idDossier));

                // Update dossier status to ACCEPTER
                dossier.setStatus(DossierStatus.ACCEPTER);

                // Save the updated dossier with the new status
                dossierRepository.save(dossier);

                // Perform any additional operations such as saving comments, auditing, etc.
                // ...

                // Optionally, you can log each dossier ID for debugging purposes
                System.out.println("Dossier status set to ACCEPTER for ID: " + idDossier);
            } catch (RuntimeException e) {
                // Log or handle the exception as needed
                String errorMessage = "Error processing dossier with ID: " + idDossier + ". " + e.getMessage();
                System.err.println(errorMessage);
                throw new RuntimeException(errorMessage);
            } catch (Exception e) {
                // Log or handle other exceptions
                String errorMessage = "Unexpected error processing dossier with ID: " + idDossier + ". " + e.getMessage();
                System.err.println(errorMessage);
                throw new RuntimeException(errorMessage);
            }
        }
    }



    @Override
    @Transactional
    public void setDossiersStatusToRefuser(List<Long> dossierIds, String comment, Long idCompte) {
        for (Long idDossier : dossierIds) {
            try {
                // Retrieve the dossier by its ID
                Dossier dossier = dossierRepository.findById(idDossier)
                        .orElseThrow(() -> new RuntimeException("Dossier not found with ID: " + idDossier));

                // Update dossier status to REFUSER
                dossier.setStatus(DossierStatus.REFUSER);

                // Save the updated dossier with the new status
                dossierRepository.save(dossier);

                // Perform any additional operations such as saving comments, auditing, etc.
                // ...

                // Optionally, you can log each dossier ID for debugging purposes
                System.out.println("Dossier status set to REFUSER for ID: " + idDossier);
            } catch (RuntimeException e) {
                // Log or handle the exception as needed
                String errorMessage = "Error processing dossier with ID: " + idDossier + ". " + e.getMessage();
                System.err.println(errorMessage);
                throw new RuntimeException(errorMessage);
            } catch (Exception e) {
                // Log or handle other exceptions
                String errorMessage = "Unexpected error processing dossier with ID: " + idDossier + ". " + e.getMessage();
                System.err.println(errorMessage);
                throw new RuntimeException(errorMessage);
            }
        }
    }


    ///////////////////


    @Override
    @Transactional
    public void addCommentToDossier(Long idDossier, String comment, Long idCompte) {
        try {
            // Retrieve the dossier by its ID
            Dossier dossier = dossierRepository.findById(idDossier)
                    .orElseThrow(() -> new DossierNotFoundException(idDossier));

            // Check if a comment is provided and save it to the Commentaire entity
            if (comment != null && !comment.isEmpty()) {
                // Create a new Commentaire instance
                Commentaire commentaire = new Commentaire();

                // Set the dossier for the comment
                commentaire.setDossier(dossier);

                // Set only the content of the comment
                commentaire.setComment(comment);

                // Set the status of the comment to the current dossier status
                commentaire.setStatus(dossier.getStatus());

                // Set the comment date to the current date and time
                commentaire.setCommentDate(LocalDateTime.now());

                // Retrieve the associated Compte by its ID
                Compte compte = compteRepository.findById(idCompte)
                        .orElseThrow(() -> new CompteNotFoundException(idCompte));

                // Set the associated Compte for the comment
                commentaire.setCompte(compte);

                // Save the comment to the database
                commentaireRepository.save(commentaire);
            }
        } catch (DossierNotFoundException | CompteNotFoundException e) {
            // Handle the custom exceptions
            // You can log the error, send a specific response, or perform other error handling actions
            e.printStackTrace(); // for demonstration, you may want to replace this with appropriate error handling
        }
    }



    // Custom exception for dossier not found
    public class DossierNotFoundException extends RuntimeException {
        public DossierNotFoundException(Long id) {
            super("Dossier not found with ID: " + id);
        }
    }

    // Custom exception for compte not found
    public class CompteNotFoundException extends RuntimeException {
        public CompteNotFoundException(Long id) {
            super("Compte not found with ID: " + id);
        }
    }


}



