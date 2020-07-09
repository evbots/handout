'use strict';

class Profile {
  constructor(domain, name, status) {
    this.domain = domain;
    this.name = name;
    this.status = status.replace(/'/g, '&apos;').replace(/"/g, '&quot;');
  }

  render() {
    let source = '<link rel="stylesheet" href="css/normalize.css">';
    source += '<link rel="stylesheet" href="css/milligram.css">';
    source += this.status;

    return `
<HTML>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta charset="utf-8">
  <link rel="stylesheet" href="css/normalize.css">
  <link rel="stylesheet" href="css/milligram.css">
  <link rel="apple-touch-icon" sizes="180x180" href="img/apple-touch-icon.png">
  <link rel="icon" type="image/png" sizes="32x32" href="img/favicon-32x32.png">
  <link rel="icon" type="image/png" sizes="16x16" href="img/favicon-16x16.png">

<title>${this.name} . Proof Of Concept</title>
</head>
<body>

  <div class="header" style="text-align:center">
    <br>
    <h1>${this.name}</h1>
    <a href="https://${this.domain}/">
      <h3>. Proof Of Concept</h3>
    </a>
  </div>
  <hr>

  <div class="profile container">
    <div class="row">
      <div class="column"></div>
      <div class="column">
        <h3>Status:</h3>
        <div class="status">
          <iframe style="border:none;max-height:25em;width:100%" srcdoc='${source}' onload="this.height=this.contentWindow.document.body.scrollHeight;"></iframe>
        </div>
      </div>
      <div class="column"></div>
    </div>
    <br>
    <div style="text-align:center">
      <small>If this is your subdomain, you can <a href="/edit">edit your status.</a></small>
    </div>
  </div>
  <hr>


  <div class="footer" style="padding:10px">
    <a href="about.html">About this website</a>
  </div>

</body>

    `;
  }
}

module.exports = Profile;
