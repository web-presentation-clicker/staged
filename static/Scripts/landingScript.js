// Quick function for testing
function testFunction(){
    console.log("I'M ALIVE!!!");
}

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
    } else if (userAgent.includes("Safari")){
        downloadButton.href = ""    // path to Safari extension -- TO BE ADDED
    } else {
        downloadButton.href = ""    // default link -- TO BE ADDED
    }
}

window.onload = setDownloadLink;