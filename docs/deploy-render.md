# Deploying to Render

EchoCrypt runs on Render as one Docker web service (the API also serves the built client) plus a Render Key Value instance for Redis. Messages, users and keys live in MongoDB Atlas. Render provides HTTPS, which Web Crypto requires.

Everything runs on free tiers. The free web service sleeps after 15 minutes without traffic; the first request afterwards takes 30–60 seconds while it starts. Sessions and data are unaffected, and the client reconnects on its own.

## 1. Create the database (MongoDB Atlas)

1. Create a free **M0** cluster at [mongodb.com/atlas](https://www.mongodb.com/atlas), ideally in a region close to Render's `oregon` (for example AWS `us-west-2`).
2. **Database Access:** add a database user with a password (read and write to any database).
3. **Network Access:** add `0.0.0.0/0`. Render's free tier has no fixed outbound IP; the database user's password protects the cluster.
4. **Connect → Drivers:** copy the connection string and add the database name `echocrypt` after the host:

   ```
   mongodb+srv://USER:PASSWORD@cluster0.xxxxx.mongodb.net/echocrypt?retryWrites=true&w=majority
   ```

   URL-encode special characters in the password (`@` becomes `%40`, and so on).

## 2. Deploy the Blueprint

1. In the Render dashboard choose **New → Blueprint** and select this repository.
2. Render reads [`render.yaml`](../render.yaml) and plans two resources: the `echocrypt` web service and the `echocrypt-kv` Key Value instance.
3. Paste the Atlas connection string as `MONGO_URL` and apply.

`JWT_SECRET` is generated automatically and `REDIS_URL` is wired to the Key Value instance. Once the build finishes, the app is at `https://echocrypt-xxxx.onrender.com`; `/health` should report `"ok": true`.

Every push to `main` redeploys.

## 3. Check the client IP

The per-IP sign-up and login limits depend on the server seeing each visitor's real IP, which depends on how many proxies sit in front of it (`TRUST_PROXY`, default `1`).

After deploying, sign in once and open the service's **Logs**. Each request line has a `clientIp`. It should match your public IP (search "what is my IP"). If it shows a private or proxy address instead, set `TRUST_PROXY` to `2` under **Environment** and redeploy, then check again.

## 4. Keep it awake (optional, free)

A free Render service sleeps after 15 minutes without traffic. To avoid the 30–60 second wake-up, ping it every 5 minutes with [UptimeRobot](https://uptimerobot.com) (free plan):

1. **Add New Monitor** → type **HTTP(s)**.
2. URL: `https://echocrypt-xxxx.onrender.com/health`, interval **5 minutes**.
3. Save. You also get an email if the app goes down.

One service running all month uses about 744 of the 750 free instance hours Render gives each workspace.

## 5. Optional: sign in with Google, GitHub or email

Each method appears on the sign-in page only once its variables are set. Add them in Render under **echocrypt → Environment**, then **Save Changes** (Render redeploys). Replace `echocrypt-xxxx.onrender.com` below with your real address.

These methods sign users in, but cannot unlock encryption keys (see the README). Users link Google or GitHub to an existing account under **Security** (shield icon) and can then use one-click sign-in.

### Google (free)

1. Open [console.cloud.google.com](https://console.cloud.google.com), create a project named `EchoCrypt`.
2. **APIs & Services → OAuth consent screen** (Google Auth Platform): app name `EchoCrypt`, your email as support and developer contact, audience **External**.
3. **Clients → Create client → Web application**. Under **Authorized redirect URIs** add:
   `https://echocrypt-xxxx.onrender.com/api/auth/oauth/google/callback`
4. Copy the client ID and secret into Render as `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.
5. **Branding**: application home page `https://echocrypt-xxxx.onrender.com`, privacy policy `https://echocrypt-xxxx.onrender.com/privacy`, terms of service `https://echocrypt-xxxx.onrender.com/terms`. Set `CONTACT_EMAIL` in Render so those pages show where to send data requests.
6. **Audience → Publish app**, so accounts other than test users can sign in. The app only asks for `openid email`, which needs no Google review.

### GitHub (free)

1. GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**.
2. Homepage URL: `https://echocrypt-xxxx.onrender.com`
   Authorization callback URL: `https://echocrypt-xxxx.onrender.com/api/auth/oauth/github/callback`
3. **Register application**, then **Generate a new client secret**.
4. Add `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` in Render.

### Email codes (free, Brevo)

Codes are sent through [Brevo](https://www.brevo.com)'s HTTPS API (free plan: 300 emails a day). It uses HTTPS rather than SMTP, so it works on hosts that block outgoing mail ports.

1. Create a free Brevo account.
2. **Senders, Domains & Dedicated IPs → Senders → Add a sender** with your own address and confirm it from your inbox.
3. **SMTP & API → API Keys → Generate a new API key**.
4. Add `BREVO_API_KEY` (the key) and `MAIL_FROM` (the confirmed sender address) in Render.

Mail from a free webmail sender (for example Gmail) is sometimes filtered as spam. A sender on a domain you own, verified in Brevo, delivers best.

### Passkeys

Passkeys need nothing to set up. They are tied to the exact address of the site, which the server takes from `RENDER_EXTERNAL_URL` (set by Render). If you later add a custom domain, set `PUBLIC_URL` to it; passkeys created on the old address keep working only there.

## Notes

- **Do not change `JWT_SECRET`** once users exist; it signs everyone out (no data is lost).
- The free Key Value instance does not persist to disk. That is fine: it only holds presence, rate-limit counters and the Socket.io event bus. Everything permanent is in MongoDB.
- Running more than one instance requires a paid plan; the Redis adapter already handles it, and `JWT_SECRET` is shared through the environment.
