import os

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_security import (
    Security,
    SQLAlchemyUserDatastore,
    auth_required,
    permissions_required,
    current_user,
)
from flask_security.models import fsqla_v3 as fsqla

# NEW IMPORTS FOR IDENTITY
from flask_principal import identity_loaded, RoleNeed, AnonymousIdentity, Need, identity_changed

# --- Initialize Flask app ---
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
app.config["SECRET_KEY"] = "supersecretkey"
app.config["SECURITY_PASSWORD_SALT"] = "somesalt"
app.config["SECURITY_REGISTERABLE"] = True
app.config["SECURITY_TRACKABLE"] = True
app.config["SECURITY_PASSWORD_HASH"] = "argon2"

# Mail Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER',
                                                   app.config['MAIL_USERNAME'])

# Initialize extensions
db = SQLAlchemy(app)

# Initialize Flask-Mail
mail = Mail(app)

# --- Association tables ---

# Define models and
# Initialize FsModels with our SQLAlchemy instance
fsqla.FsModels.set_db_info(db)

roles_permissions = db.Table(
    "roles_permissions",
    db.Column("role_id",
              db.Integer,
              db.ForeignKey("role.id"),
              primary_key=True),
    db.Column("permission_id",
              db.Integer,
              db.ForeignKey("permission.id"),
              primary_key=True),
)

users_permissions = db.Table(
    "users_permissions",
    db.Column("user_id",
              db.Integer,
              db.ForeignKey("user.id"),
              primary_key=True),
    db.Column("permission_id",
              db.Integer,
              db.ForeignKey("permission.id"),
              primary_key=True),
)


class PermissionModel(db.Model):
    """A separate table to store permission names."""
    __tablename__ = "permission"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def __repr__(self):
        return f"{self.name}"

    def __str__(self):
        return f"{self.name}"


class Role(db.Model, fsqla.FsRoleMixin):
    """Flask-Security Role model, extended to have many Permissions."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)

    permissions = db.relationship(
        "PermissionModel",
        secondary=roles_permissions,
        backref=db.backref("roles", lazy="dynamic"),
    )

    def __repr__(self):
        return f"<Role {self.name}>"


class User(db.Model, fsqla.FsUserMixin):
    """Flask-Security User model, extended to have direct Permissions."""
    permissions = db.relationship(
        "PermissionModel",
        secondary=users_permissions,
        backref=db.backref("users", lazy="dynamic"),
    )

    def has_permissions(self, permission_names):
        """
        Override the check so `@permissions_required(names)` verifies:
            1) Direct user permissions
            2) Permissions via any role
        """
        if isinstance(permission_names, str):
            permission_names = [permission_names]

        for permission_name in permission_names:
            has_this_permission = False
            # Check direct user permissions
            for p in self.permissions:
                if p.name == permission_name:
                    has_this_permission = True
                    break

            # If not found in direct permissions, check role permissions
            if not has_this_permission:
                for role in self.roles:
                    for rp in role.permissions:
                        if rp.name == permission_name:
                            has_this_permission = True
                            break
                    if has_this_permission:
                        break

            if not has_this_permission:
                return False

        return True

    def get_security_payload(self):
        """Return a dictionary of user information for Flask-Security."""
        rv = super().get_security_payload()
        all_permissions = set()

        for p in self.permissions:
            all_permissions.add(p.name)

        for role in self.roles:
            for p in role.permissions:
                all_permissions.add(p.name)

        rv['permissions'] = list(all_permissions)
        return rv

    def __repr__(self):
        return f"<User {self.email}>"


class WebAuthn(db.Model, fsqla.FsWebAuthnMixin):
    pass


# --- Setup Flask-Security ---
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore, mail_util=mail)


# --- Identity Loaded Signal Handler ---
@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    """
    Ensure that the identity object is updated with the
    current user's roles and permissions *before* any checks.
    """
    if not current_user.is_authenticated:
        identity_changed.send(app,
                              identity=AnonymousIdentity())  # Reset identity
        # identity.provides.update(None)
        return

    identity.user = current_user

    # Add any 'role' Needs
    for role in current_user.roles:
        identity.provides.add(RoleNeed(role.name))

    # Add direct user permissions as fsperm Needs
    for perm in current_user.permissions:
        identity.provides.add(Need('fsperm', perm.name))

    # Add role-based permissions
    for role in current_user.roles:
        for rp in role.permissions:
            identity.provides.add(Need('fsperm', rp.name))


def create_and_seed_db():
    db.create_all()

    print("Using password hash:", app.config["SECURITY_PASSWORD_HASH"])

    def get_or_create_permission(name: str) -> PermissionModel:
        perm = PermissionModel.query.filter_by(name=name).first()
        if not perm:
            perm = PermissionModel(name=name)
            db.session.add(perm)
            db.session.commit()
        return perm

    admin_perm = get_or_create_permission("admin")
    read_perm = get_or_create_permission("read")
    write_perm = get_or_create_permission("write")
    other_perm = get_or_create_permission("other")

    admin_role = user_datastore.find_role("admin")
    if not admin_role:
        admin_role = user_datastore.create_role(name="admin")
        db.session.add(admin_role)

    user_role = user_datastore.find_role("user")
    if not user_role:
        user_role = user_datastore.create_role(name="user")
        db.session.add(user_role)

    db.session.commit()

    def add_perm_to_role(role: Role, perm: PermissionModel):
        if perm not in role.permissions:
            role.permissions.append(perm)

    # Admin role: admin, read, write
    add_perm_to_role(admin_role, admin_perm)
    add_perm_to_role(admin_role, read_perm)
    add_perm_to_role(admin_role, write_perm)

    # User role: read
    add_perm_to_role(user_role, read_perm)

    db.session.commit()

    admin_user = user_datastore.find_user(email="admin@example.com")
    if not admin_user:
        admin_user = user_datastore.create_user(
            email="admin@example.com",
            password="password",
            roles=[admin_role],
        )
        db.session.add(admin_user)
    else:
        admin_user.password = "password"

    direct_user = user_datastore.find_user(email="direct@example.com")
    if not direct_user:
        direct_user = user_datastore.create_user(
            email="direct@example.com",
            password="password",
            roles=[user_role],
        )
        db.session.add(direct_user)
    else:
        direct_user.password = "password"

    db.session.commit()

    # Give "direct" user the `other` permission directly
    # at a user level, not through roll
    if other_perm not in direct_user.permissions:
        direct_user.permissions.append(other_perm)
        db.session.commit()


# Initialize the database on startup
with app.app_context():
    create_and_seed_db()


@app.route("/admin")
@auth_required("session")
@permissions_required("admin")
def admin_dashboard():
    from flask_security import current_user
    from flask import request

    print(f"Request headers: {dict(request.headers)}")
    print(f"User: {current_user.email}")
    print(
        f"User has admin permission? {current_user.has_permissions('admin')}")

    roles = [role.name for role in current_user.roles]
    print(f"User roles: {roles}")

    all_perms = []
    for role in current_user.roles:
        role_perms = [p.name for p in role.permissions]
        print(f"Role {role.name} permissions: {role_perms}")
        all_perms.extend(role_perms)

    print(f"All permissions via roles: {all_perms}")

    if current_user.has_permissions('admin'):
        return jsonify({
            "message": "You have ADMIN access!",
            "debug_info": {
                "user": current_user.email,
                "roles": roles,
                "permissions": all_perms
            }
        })
    else:
        return jsonify({
            "error": "Forbidden",
            "debug_info": {
                "user": current_user.email,
                "roles": roles,
                "permissions": all_perms,
                "has_admin_permission": current_user.has_permissions('admin')
            }
        }), 403


@app.route("/read")
@auth_required("session")
@permissions_required("read")
def read_something():
    return jsonify({"message": "You have READ access!"})


@app.route("/write")
@auth_required("session")
@permissions_required("write")
def write_something():
    return jsonify({"message": "You have WRITE access!"})


@app.route("/other")
@auth_required("session")
@permissions_required("other")
def other():
    return jsonify({"message": "You have OTHER access!"})


if __name__ == "__main__":
    app.run(debug=True)
