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

## Notes

- **Do not change `JWT_SECRET`** once users exist; it signs everyone out (no data is lost).
- The free Key Value instance does not persist to disk. That is fine: it only holds presence, rate-limit counters and the Socket.io event bus. Everything permanent is in MongoDB.
- Running more than one instance requires a paid plan; the Redis adapter already handles it, and `JWT_SECRET` is shared through the environment.
