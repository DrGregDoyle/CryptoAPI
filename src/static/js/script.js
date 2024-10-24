function showTab(tabId) {
        // Hide all cards
        const cards = document.querySelectorAll('.card');
        cards.forEach(card => card.classList.add('hidden'));

        // Remove active class from all tabs
        const tabs = document.querySelectorAll('.tab');
        tabs.forEach(tab => tab.classList.remove('active'));

        // Show the selected card and make the tab active
        document.getElementById(tabId).classList.remove('hidden');
        event.target.classList.add('active');
    }

// Generate Keys card
// Function to generate a random private key
function generatePrivateKey() {
    fetch('/generate_private_key')
        .then(response => response.json())
        .then(data => {
            // Display the generated private key
            document.getElementById('private-key').value = data.private_key;
        })
        .catch(error => console.error('Error:', error));
}
// Function to get public keys from the inputted private key
function getPublicKeys() {
    const privateKey = document.getElementById('private-key').value.trim();

    if (!privateKey) {
        alert("Please enter or generate a private key first.");
        return;
    }

    fetch('/get_public_keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ private_key: privateKey })
    })
    .then(response => response.json())
    .then(data => {
        // Display the public keys
        document.getElementById('public-key-x').value = data.public_key_x;
        document.getElementById('public-key-y').value = data.public_key_y;
        document.getElementById('compressed-public-key').value = data.compressed_public_key;
    })
    .catch(error => console.error('Error:', error));
}
// Function to sign a message
function signMessage() {
    const privateKey = document.getElementById('sign-private-key').value.trim();
    const message = document.getElementById('sign-message').value;

    const data = {
        private_key: privateKey,
        message: message
    };

    fetch('/sign_message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        // Display the r and s components of the signature and the DER encoding
        document.getElementById('signature-r').value = data.r;
        document.getElementById('signature-s').value = data.s;
        document.getElementById('der-signature').value = data.der
    })
    .catch(error => console.error('Error:', error));
}

// Function to hash input with SHA-256
function hashSHA256() {
    const input = document.getElementById('sha256-input').value;

    fetch('/hash_sha256', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: input })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('sha256-result').value = data.hash;
    })
    .catch(error => console.error('Error:', error));
}



// Function to generate Bitcoin address
function generateBitcoinAddress() {
    const pubkeyX = document.getElementById('pubkey-x').value.trim();
    const pubkeyY = document.getElementById('pubkey-y').value.trim();
    const compressedKey = document.getElementById('pubkey-compressed').value.trim();
    const addressType = document.getElementById('address-type').value;

    // Check if the compressed public key is filled
    if (compressedKey) {
        // Generate address using compressed public key
        generateAddressFromCompressed(compressedKey, addressType);
    } else {
        // Validate the x and y coordinates
        if (pubkeyX && !pubkeyY) {
            alert("Y-coordinate is missing. Please enter it.");
            return;
        } else if (!pubkeyX && pubkeyY) {
            alert("X-coordinate is missing. Please enter it.");
            return;
        } else if (pubkeyX && pubkeyY) {
            // Generate address using public key points
            generateAddressFromPoints(pubkeyX, pubkeyY, addressType);
        } else {
            alert("Please enter either the public key points (X and Y) or the compressed public key.");
        }
    }
}

// Function to generate address from compressed public key
function generateAddressFromCompressed(compressedKey, addressType) {
    const requestData = { compressed_public_key: compressedKey, address_type: addressType };

    fetch('/generate_bitcoin_address', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestData)
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('btc-address-result').value = data.bitcoin_address;
    })
    .catch(error => console.error('Error:', error));
}

// Function to generate address from public key points
function generateAddressFromPoints(pubkeyX, pubkeyY, addressType) {
    const requestData = { public_key_x: pubkeyX, public_key_y: pubkeyY, address_type: addressType };

    fetch('/generate_bitcoin_address', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestData)
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('btc-address-result').value = data.bitcoin_address;
    })
    .catch(error => console.error('Error:', error));
}

// Function to verify a signature
function verifySignature() {
    const compressedPubKey = document.getElementById('sign-cpk').value.trim();
//    const publicKeyX = document.getElementById('verify-public-key-x').value.trim();
//    const publicKeyY = document.getElementById('verify-public-key-y').value.trim();
    const signatureR = document.getElementById('signature-r-verify').value.trim();
    const signatureS = document.getElementById('signature-s-verify').value.trim();
    const message = document.getElementById('verify-message').value;
    const dersig = document.getElementById('der-signature-verify')

    const data = {
//        public_key_x: publicKeyX,
//        public_key_y: publicKeyY,
        cpk: compressedPubKey,
        message: message,
        r: signatureR,
        s: signatureS
    };

    fetch('/verify_signature', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('verification-result').value = data.is_valid ? 'Valid' : 'Invalid';
    })
    .catch(error => console.error('Error:', error));
}