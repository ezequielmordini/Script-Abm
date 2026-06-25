import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
import boto3

logging.basicConfig(
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    level=logging.INFO
)
log = logging.getLogger(__name__)


@dataclass
class ABMRequest:
    ticket_id: str
    operation: str        # ALTA | BAJA | MODIFICACION
    username: str
    email: str
    full_name: str
    department: str
    cost_center: str
    role: str
    manager: str
    groups: list
    aws_account_id: Optional[str] = None


def validate(req: ABMRequest) -> list[str]:
    """Devuelve una lista de errores. Si esta vacia, el request es valido."""
    errors = []
    if not req.cost_center:
        errors.append('Falta centro de costos.')
    if not req.role:
        errors.append('Falta rol.')
    if not req.manager:
        errors.append('Falta manager.')
    if '@' not in req.email:
        errors.append('Email invalido.')
    if req.operation not in ('ALTA', 'BAJA', 'MODIFICACION'):
        errors.append(f'Operacion invalida: {req.operation}')
    return errors


class ActiveDirectory:
    def __init__(self, url, bind_dn, password, base_dn):
        self.base_dn = base_dn
        srv = Server(url, get_info=ALL)
        self.conn = Connection(srv, user=bind_dn, password=password,
                               auto_bind=True, receive_timeout=10)

    def _search(self, username):
        self.conn.search(self.base_dn, f'(sAMAccountName={username})',
                         attributes=['userAccountControl', 'distinguishedName'])
        return self.conn.entries[0] if self.conn.entries else None

    def exists(self, username) -> bool:
        return self._search(username) is not None

    def is_enabled(self, username) -> bool:
        entry = self._search(username)
        if not entry:
            return False
        # El bit 1 de userAccountControl indica cuenta deshabilitada
        return not bool(int(entry.userAccountControl.value) & 2)

    def create(self, req: ABMRequest):
        # Si ya existe y esta activo, no hacemos nada (idempotente)
        if self.exists(req.username):
            if self.is_enabled(req.username):
                log.info(f'AD: {req.username} ya existe y esta activo. Sin accion.')
                return
            else:
                # Caso reingreso: rehabilitar la cuenta existente
                self._set_enabled(req.username, True)
                return

        dn = f'CN={req.full_name},OU={req.department},OU=Users,{self.base_dn}'
        self.conn.add(dn, ['top', 'person', 'organizationalPerson', 'user'], {
            'sAMAccountName': req.username,
            'userPrincipalName': req.email,
            'displayName': req.full_name,
            'department': req.department,
            'extensionAttribute1': req.cost_center,
        })
        if self.conn.result['result'] != 0:
            raise RuntimeError(f'AD error al crear: {self.conn.result["description"]}')
        log.info(f'AD: usuario {req.username} creado correctamente.')

    def disable(self, username: str):
        if not self.exists(username):
            log.warning(f'AD: {username} no existe, nada que deshabilitar.')
            return
        if not self.is_enabled(username):
            log.info(f'AD: {username} ya esta deshabilitado. Sin accion.')
            return
        self._set_enabled(username, False)
        self._move_to_offboarding(username)
        log.info(f'AD: {username} deshabilitado y movido a OU=Offboarded.')

    def _set_enabled(self, username, enabled: bool):
        entry = self._search(username)
        dn = str(entry.distinguishedName)
        uac = 512 if enabled else 514
        self.conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [uac])]})
        if self.conn.result['result'] != 0:
            raise RuntimeError(f'Error al modificar UAC: {self.conn.result["description"]}')

    def _move_to_offboarding(self, username):
        # No borramos la cuenta todavia: la movemos a una OU separada
        # para mantener el historial y facilitar auditorias
        entry = self._search(username)
        dn = str(entry.distinguishedName)
        self.conn.modify_dn(dn, f'CN={username}',
                            new_superior=f'OU=Offboarded,{self.base_dn}')


class AWSIAM:
    def __init__(self):
        self.client = boto3.client('iam')

    def revoke(self, username: str):
        try:
            # Desactivar access keys (no borrar: quedan para auditoria)
            for key in self.client.list_access_keys(UserName=username)['AccessKeyMetadata']:
                self.client.update_access_key(
                    UserName=username,
                    AccessKeyId=key['AccessKeyId'],
                    Status='Inactive'
                )
            # Sacar de grupos IAM
            for group in self.client.list_groups_for_user(UserName=username)['Groups']:
                self.client.remove_user_from_group(
                    GroupName=group['GroupName'], UserName=username
                )
            # Detach de policies
            for policy in self.client.list_attached_user_policies(UserName=username)['AttachedPolicies']:
                self.client.detach_user_policy(
                    UserName=username, PolicyArn=policy['PolicyArn']
                )
            # Tag para saber cuándo fue dado de baja
            self.client.tag_user(UserName=username, Tags=[
                {'Key': 'Status', 'Value': 'offboarded'},
                {'Key': 'OffboardedAt', 'Value': datetime.now(timezone.utc).isoformat()}
            ])
            log.info(f'AWS: accesos de {username} revocados.')
        except self.client.exceptions.NoSuchEntityException:
            # Si el usuario no existe en IAM, no hay nada que hacer
            log.warning(f'AWS: {username} no existe en IAM. Sin accion.')


def process(req: ABMRequest, ad: ActiveDirectory, aws: AWSIAM) -> dict:
    result = {'ticket': req.ticket_id, 'ok': False, 'errors': [], 'systems': []}

    errors = validate(req)
    if errors:
        result['errors'] = errors
        log.warning(f'Ticket {req.ticket_id} rechazado por validacion: {errors}')
        return result

    try:
        if req.operation == 'ALTA':
            ad.create(req)
            result['systems'].append('AD')
        elif req.operation == 'BAJA':
            ad.disable(req.username)
            result['systems'].append('AD')
            if req.aws_account_id:
                aws.revoke(req.username)
                result['systems'].append('AWS-IAM')
        result['ok'] = True
    except RuntimeError as e:
        result['errors'].append(str(e))
        log.error(f'Error procesando ticket {req.ticket_id}: {e}')

    return result
