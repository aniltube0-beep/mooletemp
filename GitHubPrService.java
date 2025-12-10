package com.demo.demo.Services;

import com.demo.demo.strategy.StrategyFactory;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.kohsuke.github.*;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

@Service
public class GitHubPrService {

    // HARDCODED CONFIG FOR DEMO (Move these to application.properties in production)
    private static final String APP_ID = "123456"; // REPLACE WITH YOUR APP ID
    private static final String PRIVATE_KEY_PATH = "src/main/resources/private-key.pem";

    private final StrategyFactory strategyFactory = new StrategyFactory();

    public String createPullRequest(Long installationId, String repoUrl, String baseBranch,
                                    String fileName, String packageName, String newVersion) throws Exception {

        // 1. Authenticate and Get Client
        GitHub github = authenticateApp(installationId);

        // 2. Resolve Repository Name (from URL)
        String repoName = extractRepoName(repoUrl);
        GHRepository repo = github.getRepository(repoName);

        // 3. Setup Branches
        String headSha = repo.getBranch(baseBranch).getSHA1();
        String newBranchName = "chore/upgrade-" + packageName.replace(":", "-") + "-" + newVersion;

        // Check if branch exists to avoid crash
        try {
            repo.getRef("heads/" + newBranchName);
            return "Branch " + newBranchName + " already exists. Skipping.";
        } catch (Exception e) {
            repo.createRef("refs/heads/" + newBranchName, headSha);
        }

        // 4. Fetch File Content
        GHContent contentObj = repo.getFileContent(fileName, newBranchName);
        String fileContent = contentObj.getContent();

        // 5. Parse and Update
        String updatedContent = strategyFactory.getStrategy(fileName)
                .updateDependency(fileContent, packageName, newVersion);

        if (fileContent.equals(updatedContent)) {
            return "No changes detected. Is the version already up to date?";
        }

        // 6. Commit Changes
        repo.createContent()
                .path(fileName)
                .content(updatedContent)
                .branch(newBranchName)
                .message("build: bump " + packageName + " to " + newVersion)
                .sha(contentObj.getSha())
                .commit();

        // 7. Create Pull Request
        GHPullRequest pr = repo.createPullRequest(
                "Bump " + packageName + " to " + newVersion,
                "Automated PR created by MyJavaApp",
                newBranchName,
                baseBranch
        );

        return pr.getHtmlUrl().toString();
    }

    // --- AUTHENTICATION HELPERS ---

    private GitHub authenticateApp(long installationId) throws Exception {
        // Step A: Generate JWT
        String jwt = generateJWT();

        // Step B: Connect as the "App" to get the Installation Token
        GitHub appClient = new GitHubBuilder().withJwtToken(jwt).build();
        GHAppInstallation installation = appClient.getApp().getInstallationById(installationId);
        GHAppInstallationToken token = installation.createToken().create();

        // Step C: Connect as the "Installation" (This allows read/write access)
        return new GitHubBuilder().withAppInstallationToken(token.getToken()).build();
    }

    private String generateJWT() throws Exception {
        // Read Private Key
        String keyContent = new String(Files.readAllBytes(new File(PRIVATE_KEY_PATH).toPath()));
        keyContent = keyContent.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);

        // Sign JWT
        return Jwts.builder()
                .setIssuer(APP_ID)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusSeconds(600))) // 10 min expiry
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    private String extractRepoName(String url) {
        // Transforms "https://github.com/owner/repo" -> "owner/repo"
        if (url.endsWith("/")) url = url.substring(0, url.length() - 1);
        String[] parts = url.split("/");
        return parts[parts.length - 2] + "/" + parts[parts.length - 1];
    }
}
