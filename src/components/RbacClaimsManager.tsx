import React, { useEffect, useState } from 'react';
import { Plus, Trash2, Save, Shield } from 'lucide-react';
import { gqlRequest } from '../lib/graphqlClient';
import type { IamSystem, Permission, Role } from '../types/iam';

interface RbacClaimsManagerProps {
  token: string;
  onNotify: (msg: string) => void;
}

const RBAC_QUERY = `
  query RbacWorkspace($systemId: ID!) {
    systems {
      id
      name
      slug
      jwtTtlSeconds
      signingAlg
    }
    rolesBySystem(systemId: $systemId) {
      id
      systemId
      name
      description
      isDefault
      permissions { id code description }
      claims { id claimKey claimValue valueType }
    }
    permissionsBySystem(systemId: $systemId) {
      id
      systemId
      code
      description
    }
  }
`;

export const RbacClaimsManager: React.FC<RbacClaimsManagerProps> = ({ token, onNotify }) => {
  const [systems, setSystems] = useState<IamSystem[]>([]);
  const [selectedSystemId, setSelectedSystemId] = useState('sys-vektor-core');
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [selectedRoleId, setSelectedRoleId] = useState<string>('');

  // Editable Role State
  const [roleName, setRoleName] = useState('');
  const [roleDesc, setRoleDesc] = useState('');
  const [roleIsDefault, setRoleIsDefault] = useState(false);
  const [selectedPermIds, setSelectedPermIds] = useState<string[]>([]);
  const [claimsDraft, setClaimsDraft] = useState<Array<{ claimKey: string; claimValue: string; valueType: string }>>([]);

  // Quick Create Role / Perm
  const [newPermCode, setNewPermCode] = useState('');
  const [newPermDesc, setNewPermDesc] = useState('');
  const [newRoleName, setNewRoleName] = useState('');

  const loadRbac = async (sysId: string) => {
    try {
      const { data } = await gqlRequest<{
        systems: IamSystem[];
        rolesBySystem: Role[];
        permissionsBySystem: Permission[];
      }>({
        token,
        query: RBAC_QUERY,
        operationName: 'RbacWorkspace',
        variables: { systemId: sysId },
      });
      setSystems(data.systems);
      setRoles(data.rolesBySystem);
      setPermissions(data.permissionsBySystem);

      const activeRole = data.rolesBySystem.find((r) => r.id === selectedRoleId) || data.rolesBySystem[0];
      if (activeRole) {
        selectRoleForEdit(activeRole);
      } else {
        setSelectedRoleId('');
      }
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao carregar matriz RBAC.');
    }
  };

  useEffect(() => {
    void loadRbac(selectedSystemId);
  }, [token, selectedSystemId]);

  const selectRoleForEdit = (role: Role) => {
    setSelectedRoleId(role.id);
    setRoleName(role.name);
    setRoleDesc(role.description);
    setRoleIsDefault(role.isDefault);
    setSelectedPermIds(role.permissions.map((p) => p.id));
    setClaimsDraft(
      role.claims.map((c) => ({
        claimKey: c.claimKey,
        claimValue: c.claimValue,
        valueType: c.valueType,
      }))
    );
  };

  const handleSaveRole = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedRoleId) return;
    try {
      await gqlRequest({
        token,
        operationName: 'UpdateRoleConfig',
        query: `
          mutation UpdateRoleConfig($id: ID!, $name: String!, $description: String, $isDefault: Boolean, $permissionIds: [ID!], $claims: [ClaimInput!]) {
            updateRole(id: $id, name: $name, description: $description, isDefault: $isDefault, permissionIds: $permissionIds, claims: $claims) {
              id
              name
            }
          }
        `,
        variables: {
          id: selectedRoleId,
          name: roleName,
          description: roleDesc,
          isDefault: roleIsDefault,
          permissionIds: selectedPermIds,
          claims: claimsDraft.filter((c) => c.claimKey.trim() !== ''),
        },
      });
      onNotify(`Role "${roleName}", permissões e claims salvos no SQLite via GraphQL.`);
      await loadRbac(selectedSystemId);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao salvar role.');
    }
  };

  const handleCreatePermission = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPermCode.trim()) return;
    try {
      await gqlRequest({
        token,
        operationName: 'CreatePerm',
        query: `
          mutation CreatePerm($systemId: ID!, $code: String!, $description: String) {
            createPermission(systemId: $systemId, code: $code, description: $description) { id code }
          }
        `,
        variables: { systemId: selectedSystemId, code: newPermCode.trim(), description: newPermDesc.trim() },
      });
      setNewPermCode('');
      setNewPermDesc('');
      onNotify('Permissão criada no sistema.');
      await loadRbac(selectedSystemId);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao criar permissão.');
    }
  };

  const handleCreateRole = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRoleName.trim()) return;
    try {
      const { data } = await gqlRequest<{ createRole: Role }>({
        token,
        operationName: 'CreateRole',
        query: `
          mutation CreateRole($input: RoleInput!) {
            createRole(input: $input) {
              id name description isDefault
              permissions { id code description }
              claims { id claimKey claimValue valueType }
            }
          }
        `,
        variables: { input: { systemId: selectedSystemId, name: newRoleName.trim(), description: '' } },
      });
      setNewRoleName('');
      onNotify(`Role "${data.createRole.name}" criada.`);
      await loadRbac(selectedSystemId);
      selectRoleForEdit(data.createRole);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao criar role.');
    }
  };

  const handleDeleteRole = async (id: string) => {
    try {
      await gqlRequest({
        token,
        operationName: 'DeleteRole',
        query: `mutation DeleteRole($id: ID!) { deleteRole(id: $id) { success message } }`,
        variables: { id },
      });
      onNotify('Role removida via GraphQL.');
      setSelectedRoleId('');
      await loadRbac(selectedSystemId);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : 'Erro ao remover role.');
    }
  };

  const currentSystem = systems.find((s) => s.id === selectedSystemId);

  // Live JWT Payload Preview constructed from current RBAC state
  const previewJwtPayload = {
    iss: 'https://smarties-gate.edge.local',
    sub: 'usr-exemplo-01',
    aud: currentSystem?.slug || 'vektor-core',
    sys: currentSystem?.slug || 'vektor-core',
    roles: roleName ? [roleName] : [],
    permissions: permissions.filter((p) => selectedPermIds.includes(p.id)).map((p) => p.code),
    claims: Object.fromEntries(
      claimsDraft
        .filter((c) => c.claimKey.trim())
        .map((c) => [
          c.claimKey,
          c.valueType === 'number'
            ? Number(c.claimValue)
            : c.valueType === 'boolean'
              ? c.claimValue === 'true'
              : c.claimValue,
        ])
    ),
    exp: Math.floor(Date.now() / 1000) + (currentSystem?.jwtTtlSeconds || 3600),
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-xl font-semibold text-white">RBAC, Permissões e Claims em JWT</h1>
          <p className="text-xs text-slate-400 mt-1">
            Agrupe permissões granulares e claims personalizadas em funções persistidas no SQLite para emissão dinâmica de JWT.
          </p>
        </div>
        <select
          value={selectedSystemId}
          onChange={(e) => {
            setSelectedSystemId(e.target.value);
            setSelectedRoleId('');
          }}
          className="bg-[#111827] border border-slate-700 rounded-md px-3.5 py-2 text-xs text-white focus:outline-none focus:border-[#F6821F]"
        >
          {systems.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name} ({s.slug})
            </option>
          ))}
        </select>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Roles & Permissions Catalog */}
        <div className="lg:col-span-4 space-y-5">
          <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-semibold text-white">Funções (Roles) do Sistema</h2>
            <div className="space-y-1.5">
              {roles.map((r) => (
                <div
                  key={r.id}
                  onClick={() => selectRoleForEdit(r)}
                  className={`flex items-center justify-between px-3 py-2 rounded-md cursor-pointer border text-xs transition-colors ${
                    selectedRoleId === r.id
                      ? 'bg-[#F6821F]/10 border-[#F6821F] text-white'
                      : 'bg-[#090D16] border-slate-800 text-slate-300 hover:border-slate-600'
                  }`}
                >
                  <div>
                    <div className="font-mono font-medium">{r.name}</div>
                    <div className="text-[11px] text-slate-400">
                      {r.permissions.length} perms · {r.claims.length} claims {r.isDefault ? '· padrão' : ''}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={(ev) => {
                      ev.stopPropagation();
                      void handleDeleteRole(r.id);
                    }}
                    className="p-1 text-slate-500 hover:text-red-400"
                    title="Remover Role"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
            <form onSubmit={handleCreateRole} className="pt-2 flex gap-2">
              <input
                type="text"
                value={newRoleName}
                onChange={(e) => setNewRoleName(e.target.value)}
                placeholder="Nova role (ex: billing_admin)"
                className="flex-1 bg-[#090D16] border border-slate-700 rounded-md px-2.5 py-1.5 text-xs font-mono text-white"
              />
              <button
                type="submit"
                className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-white rounded-md"
              >
                Criar
              </button>
            </form>
          </div>

          <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-semibold text-white">Nova Permissão Atômica</h2>
            <form onSubmit={handleCreatePermission} className="space-y-2.5">
              <input
                type="text"
                value={newPermCode}
                onChange={(e) => setNewPermCode(e.target.value)}
                placeholder="Código (ex: invoices:export)"
                className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-1.5 text-xs font-mono text-white"
              />
              <input
                type="text"
                value={newPermDesc}
                onChange={(e) => setNewPermDesc(e.target.value)}
                placeholder="Descrição"
                className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-1.5 text-xs text-white"
              />
              <button
                type="submit"
                className="w-full flex items-center justify-center gap-1.5 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-white rounded-md"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Adicionar Permissão</span>
              </button>
            </form>
          </div>
        </div>

        {/* Center/Right: Role Editor & Live JWT Payload Preview */}
        <div className="lg:col-span-8 space-y-6">
          {selectedRoleId ? (
            <form onSubmit={handleSaveRole} className="bg-[#111827] border border-slate-800/90 rounded-lg p-5 space-y-5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-[#F6821F]" />
                  <h2 className="text-sm font-semibold text-white">Editar Role e Claims</h2>
                </div>
                <button
                  type="submit"
                  className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold bg-[#F6821F] hover:bg-[#e27316] text-slate-950 rounded-md"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>Salvar via GraphQL</span>
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Nome da Role</label>
                  <input
                    type="text"
                    required
                    value={roleName}
                    onChange={(e) => setRoleName(e.target.value)}
                    className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-2 text-xs font-mono text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Descrição</label>
                  <input
                    type="text"
                    value={roleDesc}
                    onChange={(e) => setRoleDesc(e.target.value)}
                    className="w-full bg-[#090D16] border border-slate-700 rounded-md px-3 py-2 text-xs text-white"
                  />
                </div>
              </div>

              <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={roleIsDefault}
                  onChange={(e) => setRoleIsDefault(e.target.checked)}
                  className="rounded border-slate-700 bg-[#090D16]"
                />
                <span>Atribuir como função padrão em registros e provisionamento JIT</span>
              </label>

              {/* Permissions Checklist */}
              <div className="space-y-2">
                <div className="text-xs font-medium text-slate-300">Permissões Vinculadas</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {permissions.map((perm) => {
                    const checked = selectedPermIds.includes(perm.id);
                    return (
                      <label
                        key={perm.id}
                        className={`flex items-start gap-2.5 p-2.5 rounded-md border text-xs cursor-pointer transition-colors ${
                          checked
                            ? 'bg-slate-800/60 border-slate-600 text-white'
                            : 'bg-[#090D16] border-slate-800 text-slate-400'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() =>
                            setSelectedPermIds((prev) =>
                              prev.includes(perm.id) ? prev.filter((id) => id !== perm.id) : [...prev, perm.id]
                            )
                          }
                          className="mt-0.5 rounded border-slate-700 bg-[#090D16]"
                        />
                        <div>
                          <div className="font-mono text-[11px]">{perm.code}</div>
                          <div className="text-[11px] text-slate-500">{perm.description}</div>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              {/* Custom Claims Builder */}
              <div className="space-y-2.5 pt-2 border-t border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-300">Claims Personalizadas no JWT</span>
                  <button
                    type="button"
                    onClick={() =>
                      setClaimsDraft((prev) => [...prev, { claimKey: '', claimValue: '', valueType: 'string' }])
                    }
                    className="text-xs text-[#F6821F] hover:underline"
                  >
                    + Adicionar Claim
                  </button>
                </div>

                {claimsDraft.map((claim, idx) => (
                  <div key={idx} className="grid grid-cols-12 gap-2 items-center">
                    <input
                      type="text"
                      placeholder="chave (ex: tenant_tier)"
                      value={claim.claimKey}
                      onChange={(e) => {
                        const next = [...claimsDraft];
                        next[idx].claimKey = e.target.value;
                        setClaimsDraft(next);
                      }}
                      className="col-span-4 bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-white"
                    />
                    <input
                      type="text"
                      placeholder="valor"
                      value={claim.claimValue}
                      onChange={(e) => {
                        const next = [...claimsDraft];
                        next[idx].claimValue = e.target.value;
                        setClaimsDraft(next);
                      }}
                      className="col-span-4 bg-[#090D16] border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-white"
                    />
                    <select
                      value={claim.valueType}
                      onChange={(e) => {
                        const next = [...claimsDraft];
                        next[idx].valueType = e.target.value;
                        setClaimsDraft(next);
                      }}
                      className="col-span-3 bg-[#090D16] border border-slate-700 rounded px-2 py-1.5 text-xs text-slate-200"
                    >
                      <option value="string">string</option>
                      <option value="number">number</option>
                      <option value="boolean">boolean</option>
                    </select>
                    <button
                      type="button"
                      onClick={() => setClaimsDraft((prev) => prev.filter((_, i) => i !== idx))}
                      className="col-span-1 text-slate-500 hover:text-red-400 flex justify-center"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </form>
          ) : (
            <div className="bg-[#111827] border border-slate-800 rounded-lg p-8 text-center text-xs text-slate-400">
              Selecione ou crie uma Role para editar permissões e claims.
            </div>
          )}

          {/* Live JWT Payload Preview */}
          <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Pré-visualização do Payload JWT Emitido</h3>
              <span className="text-xs font-mono text-slate-400">
                {currentSystem?.signingAlg || 'RS256'} · exp +{currentSystem?.jwtTtlSeconds || 3600}s
              </span>
            </div>
            <pre className="bg-[#090D16] border border-slate-800 rounded-md p-3.5 text-xs font-mono text-emerald-300 overflow-x-auto leading-relaxed">
              {JSON.stringify(previewJwtPayload, null, 2)}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
