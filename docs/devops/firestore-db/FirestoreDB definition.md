# Collections

The following collections in the Firestore DB will be automatically created (if does not exist) when the `ivmauth` service is started:
    * `keys-journal`    - Keys Journal ...
    * `openID-providers`- OpenID Providers ...
    * `pubkyes`         - Public Keys ...

The following collections will be created when a new record is added to the DB:
    * `clients`         - Clients ...
    * `users`           - Users ...
    
# Service Account roles (permissions)

* Firestore Service Agent [`roles/firestore.serviceAgent`]
  *Gives Firestore service account access to managed resources.*

* Cloud Datastore User [`roles/datastore.user`]
  *Provides read/write access to data in a Cloud Datastore database. Intended for application developers and service accounts.*
