// Detect browser & set appropriate download link
function setDownloadLink(){
    let downloadButton = document.querySelector("#button-container a");

    // Sets the user's agent
    let userAgent = navigator.userAgent;

    // Verify browser in use & set the link
    if(userAgent.includes("Chrome")){
        downloadButton.href = ""    // path to Chrome extension -- TO BE ADDED
    } else if (userAgent.includes("Firefox")){
        downloadButton.href = ""    // path to Firefox extension -- TO BE ADDED
    }else {
        downloadButton.href = ""    // default link -- TO BE ADDED
    }
}

// Toggles menu visibility
function toggleMenu(){
    let navbar = document.getElementById("navbar-container");
    navbar.classList.toggle("show");
}

// Copies the Bitcoin wallet address
function copyBitcoinAddress(){
    let address = document.getElementById("bitcoin-address").textContent;
    navigator.clipboard.writeText(address);
}

// Copies the Monero wallet address
function copyMoneroAddress(){
    let address = document.getElementById("monero-address").textContent;
    navigator.clipboard.writeText(address);
}

window.onload = setDownloadLink;