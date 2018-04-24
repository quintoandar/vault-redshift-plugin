package main

import (
	"database/sql"
	"fmt"
	"context"
	"strings"
	"time"
	"errors"
    "crypto/md5"
    "encoding/hex"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/logical/database/dbplugin"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/plugins"
	"github.com/hashicorp/vault/plugins/helper/database/connutil"
	"github.com/hashicorp/vault/plugins/helper/database/credsutil"
	"github.com/hashicorp/vault/plugins/helper/database/dbutil"
	"github.com/lib/pq"
)

const (
	redshiftTypeName      string = "redshift"
	defaultRedshiftRenewSQL        = `
ALTER USER {{name}} VALID UNTIL '{{expiration}}';
`
	defaultRotateRootCredentialsSQL  string = `
ALTER USER "{{name}}" PASSWORD '{{password}}';
`

)

var _ dbplugin.Database = &RedShift{}

// New implements builtinplugins.BuiltinFactory
func New() (interface{}, error) {
	db := new()
	// Wrap the plugin with middleware to sanitize errors
	dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.SecretValues)
	return dbType, nil
}


func new() *RedShift {
	connProducer := &connutil.SQLConnectionProducer{}
	connProducer.Type = "postgres"

	credsProducer := &credsutil.SQLCredentialsProducer{
		DisplayNameLen: 8,
		RoleNameLen:    8,
		UsernameLen:    63,
		Separator:      "_",
	}

	dbType := &RedShift{
		SQLConnectionProducer:  connProducer,
		CredentialsProducer: credsProducer,
	}

	return dbType
}

// Run instantiates a RedShift object, and runs the RPC server for the plugin
func Run(apiTLSConfig *api.TLSConfig) error {
	dbType, err := New()
	if err != nil {
		return err
	}

	plugins.Serve(dbType.(dbplugin.Database), apiTLSConfig)

	return nil
}


type RedShift struct {
	*connutil.SQLConnectionProducer
	credsutil.CredentialsProducer
}

func (p *RedShift) Type() (string, error) {
	return redshiftTypeName, nil
}

func (p *RedShift) getConnection(ctx context.Context) (*sql.DB, error) {
	db, err := p.Connection(ctx)
	if err != nil {
		return nil, err
	}

	return db.(*sql.DB), nil
}

func (p *RedShift) CreateUser(ctx context.Context, statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, expiration time.Time) (username string, password string, err error) {
	if statements.CreationStatements == "" {
		return "", "", dbutil.ErrEmptyCreationStatement
	}

	// Grab the lock
	p.Lock()
	defer p.Unlock()

	username, err = p.GenerateUsername(usernameConfig)
	if err != nil {
		return "", "", err
	}
    
    username = strings.ToLower(username)
	username = strings.Replace(username, "-", "_", -1)

	password, err = p.GeneratePassword()
	if err != nil {
		return "", "", err
	}
    
    pwdMD5 := md5.New()
    pwdMD5.Write([]byte(password));
    pwdMD5.Write([]byte(username));
    passwordMD5  := "md5" + hex.EncodeToString(pwdMD5.Sum(nil))
	expirationStr, err := p.GenerateExpiration(expiration)
	if err != nil {
		return "", "", err
	}

	// Get the connection
	db, err := p.getConnection(ctx)
	if err != nil {
		return "", "", err

	}

	// Start a transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err

	}
	defer func() {
		tx.Rollback()
	}()

	// Execute each query
	for _, query := range strutil.ParseArbitraryStringSlice(statements.CreationStatements, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}

		stmt, err := tx.Prepare(dbutil.QueryHelper(query, map[string]string{
			"name":       username,
			"password":   passwordMD5,
			"expiration": expirationStr,
		}))
		if err != nil {
			return "", "", err

		}
		defer stmt.Close()
		if _, err := stmt.ExecContext(ctx); err != nil {
			return "", "", err

		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return "", "", err

	}
    
	return username, password, nil
}

func (p *RedShift) RenewUser(ctx context.Context, statements dbplugin.Statements, username string, expiration time.Time) error {
	p.Lock()
	defer p.Unlock()

	renewStmts := statements.RenewStatements
	if renewStmts == "" {
		renewStmts = defaultRedshiftRenewSQL
	}

	db, err := p.getConnection(ctx)
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		tx.Rollback()
	}()

	expirationStr, err := p.GenerateExpiration(expiration)
	if err != nil {
		return err
	}

	for _, query := range strutil.ParseArbitraryStringSlice(renewStmts, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}
		stmt, err := tx.PrepareContext(ctx, dbutil.QueryHelper(query, map[string]string{
			"name":       username,
			"expiration": expirationStr,
		}))
		if err != nil {
			return err
		}

		defer stmt.Close()
		if _, err := stmt.ExecContext(ctx); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (p *RedShift) RevokeUser(ctx context.Context, statements dbplugin.Statements, username string) error {
	// Grab the lock
	p.Lock()
	defer p.Unlock()

	if statements.RevocationStatements == "" {
		return p.defaultRevokeUser(ctx, username)
	}

	return p.customRevokeUser(ctx, username, statements.RevocationStatements)
}

func (p *RedShift) customRevokeUser(ctx context.Context, username, revocationStmts string) error {
	db, err := p.getConnection(ctx)
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		tx.Rollback()
	}()

	for _, query := range strutil.ParseArbitraryStringSlice(revocationStmts, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}

		stmt, err := tx.PrepareContext(ctx, dbutil.QueryHelper(query, map[string]string{
			"name": username,
		}))
		if err != nil {
			return err
		}
		defer stmt.Close()

		if _, err := stmt.ExecContext(ctx); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

const (
    rs_revoke_sql string = `
select distinct schemaname from (
  select QUOTE_IDENT(schemaname) as schemaname FROM pg_tables WHERE schemaname not in ('pg_internal') 
  union 
  select QUOTE_IDENT(schemaname) as schemaname FROM pg_views WHERE schemaname not in ('pg_internal') 
)
`
)

func (p *RedShift) defaultRevokeUser(ctx context.Context, username string) error {
	db, err := p.getConnection(ctx)
	if err != nil {
		return err
	}

	// Check if the user exists
	var exists bool
	err = db.QueryRowContext(ctx, "SELECT exists (SELECT usename FROM pg_user WHERE usename=$1);", username).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	if exists == false {
		return nil
	}

	// Query for permissions; we need to revoke permissions before we can drop
	// the role
	// This isn't done in a transaction because even if we fail along the way,
	// we want to remove as much access as possible
	stmt, err := db.PrepareContext(ctx, "select 'alter table '+schemaname+'.'+tablename+' owner to rdsdb;' as sql from pg_tables where tableowner like $1;")
	if err != nil {
		return err
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx, username)
	if err != nil {
		return err
	}
	defer rows.Close()

	const initialNumRevocations = 16
	revocationStmts := make([]string, 0, initialNumRevocations)
	for rows.Next() {
		var sql string
		err = rows.Scan(&sql)
		if err != nil {
			// keep going; remove as many permissions as possible right now
			continue
		}
		revocationStmts = append(revocationStmts, sql)
	}
	
	stmt, err = db.PrepareContext(ctx, fmt.Sprintf(`select 'revoke all on schema '+schemaname+' from %s;' as sql from (%s);`,
									   username,
									   rs_revoke_sql))
	if err != nil {
		return err
	}

	rows, err = stmt.QueryContext(ctx)
	if err != nil {
		return err
	}

	for rows.Next() {
		var sql string
		err = rows.Scan(&sql)
		if err != nil {
			// keep going; remove as many permissions as possible right now
			continue
		}
		revocationStmts = append(revocationStmts, sql)
	}

	stmt, err = db.PrepareContext(ctx, fmt.Sprintf(`select 'revoke all on all tables in schema '+schemaname+' from %s;' as sql from (%s);`,
									   username,
									   rs_revoke_sql))
	if err != nil {
		return err
	}

	rows, err = stmt.QueryContext(ctx)
	if err != nil {
		return err
	}

	for rows.Next() {
		var sql string
		err = rows.Scan(&sql)
		if err != nil {
			// keep going; remove as many permissions as possible right now
			continue
		}
		revocationStmts = append(revocationStmts, sql)
	}
	
	// again, here, we do not stop on error, as we want to remove as
	// many permissions as possible right now
	var lastStmtError error
	for _, query := range revocationStmts {
		stmt, err := db.PrepareContext(ctx, query)
		if err != nil {
			lastStmtError = err
			continue
		}
		defer stmt.Close()
		_, err = stmt.ExecContext(ctx)
		if err != nil {
			lastStmtError = err
		}
	}

	// can't drop if not all privileges are revoked
	if rows.Err() != nil {
		return errwrap.Wrapf("could not generate revocation statements for all rows: %s", rows.Err())
	}
	if lastStmtError != nil {
		return errwrap.Wrapf("could not perform all revocation statements: %s", lastStmtError)
	}

	// Drop this user
	stmt, err = db.PrepareContext(ctx, fmt.Sprintf(
		`DROP USER %s;`, pq.QuoteIdentifier(username)))
	if err != nil {
		return err
	}
	defer stmt.Close()
	if _, err := stmt.ExecContext(ctx); err != nil {
		return err
	}

	return nil
}

func (p *RedShift) RotateRootCredentials(ctx context.Context, statements []string) (map[string]interface{}, error) {
	p.Lock()
	defer p.Unlock()

	if (p.Username == "" || p.Password == "") {
		return nil, errors.New("username and password are required to rotate")
	}
	

	rotateStatents := defaultRotateRootCredentialsSQL

	db, err := p.getConnection(ctx)
	if err != nil {
		return nil, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		tx.Rollback()
	}()

	password, err := p.GeneratePassword()
	if err != nil {
		return nil, err
	}

	pwdMD5 := md5.New()
    pwdMD5.Write([]byte(password));
    pwdMD5.Write([]byte(p.Username));
    passwordMD5  := "md5" + hex.EncodeToString(pwdMD5.Sum(nil))
	
	
	for _, query := range strutil.ParseArbitraryStringSlice(rotateStatents, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}
		stmt, err := tx.PrepareContext(ctx, dbutil.QueryHelper(query, map[string]string{
			"name":       p.Username,
			"password":   passwordMD5,
		}))
		if err != nil {
			return nil, err
		}

		defer stmt.Close()
		if _, err := stmt.ExecContext(ctx); err != nil {
			return nil, err
		}
	}
	
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// Close the database connection to ensure no new connections come in
	if err := db.Close(); err != nil {
		return nil, err
	}

	p.RawConfig["password"] = passwordMD5
	return p.RawConfig, nil
}