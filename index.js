const express = require("express");
const crypto = require("crypto")

if(!globalThis.crypto){
  globalThis.crypto = crypto
}

const { generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse, generateAuthenticationOptions } = require('@simplewebauthn/server')
const PORT = 3000;
const app = express();
app.use(express.static("./public"));
app.use(express.json());

// states

const userStore = {};
const challangeStore = {}
app.post("/ragister", (req, res) => {
  const { username, passowrd } = req.body;
  const id ='user' + Date.now();

  const user = {
    id,
    username,
    passowrd,
  };

  userStore[id] = user;
  console.log("ragister successful");
  return res.json({ id });
});


app.post("/register-challenge", async(req, res) => {
    const { userId } = req.body
    console.log("userStore", userStore)
    if(!userStore[userId]) return res.json({Error: "User not found"})
    
      const challangePayload = await generateRegistrationOptions({
        rpID: 'localhost',
        rpName: 'My localhost machine',
        userName: userStore[userId].username
      })

      challangeStore[userId] = challangePayload.challenge

      return res.json({
        options: challangePayload
      })
});


app.post("/register-verify", async(req, res) => {
    const { userId, cred } = req.body
    if(!userStore[userId]) return res.json({Error: "User not found"})
    const challange = challangeStore[userId]


    const verificationResult = await verifyRegistrationResponse({
      expectedChallenge: challange,
      expectedOrigin: 'http://localhost:3000',
      expectedRPID: 'localhost',
      response: cred,
    })

    if(!verificationResult.verified) return res.json({Error: "Could not verify"})
      userStore[userId].passkey = verificationResult.registrationInfo

      return res.json({
        verified: true
      }) 
});




app.post('/login-challenge', async (req, res) => {
  const { userId } = req.body
  if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })
  
  const opts = await generateAuthenticationOptions({
      rpID: 'localhost',
  })

  challangeStore[userId] = opts.challenge

  return res.json({ options: opts })
})


app.post('/login-verify', async (req, res) => {
  const { userId, cred }  = req.body

  if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })
  const user = userStore[userId]
  const challenge = challangeStore[userId]

  const result = await verifyAuthenticationResponse({
      expectedChallenge: challenge,
      expectedOrigin: 'http://localhost:3000',
      expectedRPID: 'localhost',
      response: cred,
      authenticator: user.passkey
  })

  if (!result.verified) return res.json({ error: 'something went wrong' })
  
  // Login the user: Session, Cookies, JWT
  return res.json({ success: true, userId })
})


app.listen(PORT, () => console.log("server started on ", PORT));
