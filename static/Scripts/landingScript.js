// Detect browser & set appropriate download link
function setDownloadLink(){
    let downloadButton = document.querySelector("#button-container a");

    // Sets the user's agent
    let userAgent = navigator.userAgent;

    // Verify browser in use & set the link
    if(userAgent.includes("Chrome")){
        downloadButton.href = "https://chromewebstore.google.com/detail/web-presentation-clicker/";
    } else if (userAgent.includes("Firefox")){
        downloadButton.href = "https://addons.mozilla.org/en-US/firefox/addon/web-presentation-clicker/";
    }else {
        downloadButton.href = "#";
        downloadButton.textContent = "Browser not supported";
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