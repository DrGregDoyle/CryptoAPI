// -- Javascript functions --

// Show tab
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

// -- Generate Keys card
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

// -- Message signing card
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

// -- Message verifying card
// Function to verify a signature
function verifySignature() {
    const compressedPubKey = document.getElementById('sign-cpk').value.trim();
    const signatureR = document.getElementById('signature-r-verify').value.trim();
    const signatureS = document.getElementById('signature-s-verify').value.trim();
    const message = document.getElementById('verify-message').value;
    const dersig = document.getElementById('der-signature-verify').value;

    console.log("DER Signature:", dersig);  // Debug line

    const data = {
        cpk: compressedPubKey,
        message: message,
        r: signatureR,
        s: signatureS,
        der_sig: dersig
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

// -- Hash data card
// Function to hash input with all available HashTypes
function hash_input() {
    const input = document.getElementById('hashing-input').value;

    fetch('/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: input })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('sha256-result').value = data.sha256;
        document.getElementById('hash256-result').value = data.hash256;
        document.getElementById('ripemd160-result').value = data.ripemd160;
        document.getElementById('hash160-result').value = data.hash160;
    })
    .catch(error => console.error('Error:', error));
}

// -- Bitcoin Address card

// Function to generate pubkeyhash
function pubKeyHash() {
    const compressedPubKey = document.getElementById('pubkey-compressed').value.trim();

    console.log(compressedPubKey)

    fetch('/pubkeyhash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ compressed_public_key: compressedPubKey })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('pubkey-hash').value = data.pubkeyhash;
    })
    .catch(error => console.error('Error:', error));
}


// Function to generate Bitcoin address
function generateBitcoinAddress() {
    const addressType = document.getElementById('address-type').value;
    const hashedPubKey = document.getElementById('pubkey-hash').value.trim()

    console.log('Generate Bitcoin Address')
    console.log(addressType, hashedPubKey)

    generateAddressFromCompressed(addressType, hashedPubKey);

}

// Function to generate address from compressed public key
function generateAddressFromCompressed(addressType, hashedPubKey) {
    const requestData = {address_type: addressType, pub_key_hash: hashedPubKey };

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

//TESTING
// script.js

//document.addEventListener('DOMContentLoaded', () => {
//    const addCardButton = document.getElementById('addCardButton'); // Ensure you have this button in your HTML
//    const cardContainer = document.querySelector('.container');
//    let cardCount = 0;
//
//    addCardButton.addEventListener('click', () => {
//        cardCount += 1;
//        const newCard = document.createElement('div');
//        newCard.classList.add('card', 'visible');
//        newCard.innerHTML = `
//            <h2>New Card ${cardCount}</h2>
//            <p>This is the content of card number ${cardCount}.</p>
//            <button class="button" onclick="removeCard(this)">Remove</button>
//        `;
//
//        // Calculate offset based on current card count
//        const offset = cardCount * 10; // Adjust the multiplier for desired overlap
//        newCard.style.transform = `translateY(${offset}px) scale(${1 - cardCount * 0.02})`;
//        newCard.style.zIndex = cardCount;
//
//        cardContainer.appendChild(newCard);
//    });
//});
//
//function removeCard(button) {
//    const card = button.parentElement;
//    card.classList.remove('visible');
//    card.style.transition = 'all 0.3s ease';
//    card.style.opacity = '0';
//    card.style.transform = 'translateY(-20px) scale(0.98)';
//    setTimeout(() => {
//        card.remove();
//    }, 300);
//}
