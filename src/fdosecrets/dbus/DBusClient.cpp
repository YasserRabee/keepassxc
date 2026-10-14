/*
 *  Copyright (C) 2020 Aetf <aetf@unlimitedcode.works>
 *  Copyright (C) 2020 Jan Klötzke <jan@kloetzke.net>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "DBusClient.h"

#include "fdosecrets/FdoSecretsSettings.h"
#include "fdosecrets/dbus/DBusMgr.h"
#include "fdosecrets/objects/SessionCipher.h"

#include <utility>

namespace FdoSecrets
{
    bool ProcInfo::operator==(const ProcInfo& other) const
    {
        return this->pid == other.pid && this->ppid == other.ppid && this->exePath == other.exePath
               && this->name == other.name && this->command == other.command && this->startTime == other.startTime
               && this->tty == other.tty && this->cgroup == other.cgroup;
    }

    bool ProcInfo::operator!=(const ProcInfo& other) const
    {
        return !(*this == other);
    }

    int PeerInfo::maxRememberDepth() const
    {
        // PID 1 never exits, so tying a decision to it would cover the executable forever
        auto identified = [](const ProcInfo& proc) {
            return proc.pid > 1 && proc.startTime != 0 && !proc.exePath.isEmpty();
        };
        // a pseudo terminal (/dev/pts/N, majors 136-143), not a console a compositor may run on
        auto pty = [](int tty) {
            auto major = (tty >> 8) & 0xfff;
            return major >= 136 && major <= 143;
        };
        // a cgroup of its own, not "/" or a login session's systemd scope that holds everything
        auto ownGroup = [](const QString& cgroup) {
            auto name = cgroup.section('/', -1);
            return !name.isEmpty() && !(name.startsWith("session-") && name.endsWith(".scope"));
        };

        if (hierarchy.isEmpty() || !identified(hierarchy.front())) {
            return -1;
        }
        const auto& self = hierarchy.front();
        // a client moved into a cgroup of its own when started, like a snap, is judged by its parent's
        // cgroup, if the grandparent is in it too: launchers like the desktop shell or a terminal are not
        // in the cgroup of the process that started them
        auto group = self.cgroup;
        if (hierarchy.size() > 2 && hierarchy.at(1).cgroup != group
            && hierarchy.at(1).cgroup == hierarchy.at(2).cgroup) {
            group = hierarchy.at(1).cgroup;
        }
        int depth = 0;
        for (int i = 1; i < hierarchy.size(); ++i) {
            const auto& proc = hierarchy.at(i);
            auto sameTerminal = pty(proc.tty) && proc.tty == self.tty;
            auto sameGroup = ownGroup(proc.cgroup) && proc.cgroup == group;
            if (!identified(proc) || !(sameTerminal || sameGroup)) {
                break;
            }
            depth = i;
        }
        return depth;
    }

    bool PeerInfo::operator==(const PeerInfo& other) const
    {
        return this->address == other.address && this->pid == other.pid && this->valid == other.valid
               && this->hierarchy == other.hierarchy;
    }

    bool PeerInfo::operator!=(const PeerInfo& other) const
    {
        return !(*this == other);
    }

    DBusClient::DBusClient(DBusMgr* dbus, PeerInfo process)
        : m_dbus(dbus)
        , m_process(std::move(process))
    {
    }

    DBusMgr* DBusClient::dbus() const
    {
        return m_dbus;
    }

    QString DBusClient::name() const
    {
        auto exePath = m_process.exePath();
        if (exePath.isEmpty()) {
            return QObject::tr("unknown executable (DBus address %1)").arg(m_process.address);
        }
        if (!m_process.valid) {
            return QObject::tr("%1 (invalid executable path)").arg(exePath);
        }
        return exePath;
    }

    bool DBusClient::itemKnown(const QUuid& uuid) const
    {
        return m_authorizedAll != AuthDecision::Undecided || m_allowed.contains(uuid) || m_allowedOnce.contains(uuid)
               || m_denied.contains(uuid) || m_deniedOnce.contains(uuid);
    }

    bool DBusClient::itemAuthorized(const QUuid& uuid) const
    {
        if (!FdoSecrets::settings()->confirmAccessItem()) {
            // everyone is authorized if this is not enabled
            return true;
        }

        // check if we have catch-all decision
        if (m_authorizedAll == AuthDecision::Allowed) {
            return true;
        }
        if (m_authorizedAll == AuthDecision::Denied) {
            return false;
        }

        // individual decisions
        if (m_deniedOnce.contains(uuid) || m_denied.contains(uuid)) {
            // explicitly denied
            return false;
        }
        if (m_allowedOnce.contains(uuid) || m_allowed.contains(uuid)) {
            // explicitly allowed
            return true;
        }
        // haven't asked, not authorized by default
        return false;
    }

    bool DBusClient::itemAuthorizedResetOnce(const QUuid& uuid)
    {
        auto auth = itemAuthorized(uuid);
        m_deniedOnce.remove(uuid);
        m_allowedOnce.remove(uuid);
        return auth;
    }

    void DBusClient::setItemAuthorized(const QUuid& uuid, AuthDecision auth)
    {
        // uuid should only be in exactly one set at any time
        m_allowed.remove(uuid);
        m_allowedOnce.remove(uuid);
        m_denied.remove(uuid);
        m_deniedOnce.remove(uuid);
        switch (auth) {
        case AuthDecision::Allowed:
            m_allowed.insert(uuid);
            break;
        case AuthDecision::AllowedOnce:
            m_allowedOnce.insert(uuid);
            break;
        case AuthDecision::Denied:
            m_denied.insert(uuid);
            break;
        case AuthDecision::DeniedOnce:
            m_deniedOnce.insert(uuid);
            break;
        default:
            break;
        }
    }

    void DBusClient::setAllAuthorized(AuthDecision authorized)
    {
        // once variants doesn't make sense here
        if (authorized == AuthDecision::AllowedOnce) {
            authorized = AuthDecision::Allowed;
        }
        if (authorized == AuthDecision::DeniedOnce) {
            authorized = AuthDecision::Denied;
        }
        m_authorizedAll = authorized;
    }

    void DBusClient::clearAuthorization()
    {
        m_authorizedAll = AuthDecision::Undecided;
        m_allowed.clear();
        m_allowedOnce.clear();
        m_denied.clear();
        m_deniedOnce.clear();
    }

    void DBusClient::disconnectDBus()
    {
        clearAuthorization();
        // notify DBusMgr about the removal
        m_dbus->removeClient(this);
    }

    QSharedPointer<CipherPair>
    DBusClient::negotiateCipher(const QString& algorithm, const QVariant& input, QVariant& output, bool& incomplete)
    {
        incomplete = false;

        QSharedPointer<CipherPair> cipher{};
        if (algorithm == PlainCipher::Algorithm) {
            cipher.reset(new PlainCipher);
        } else if (algorithm == DhIetf1024Sha256Aes128CbcPkcs7::Algorithm) {
            QByteArray clientPublicKey = input.toByteArray();
            cipher.reset(new DhIetf1024Sha256Aes128CbcPkcs7(clientPublicKey));
        } else {
            // error notSupported
        }

        if (!cipher) {
            return {};
        }

        if (!cipher->isValid()) {
            qWarning() << "FdoSecrets: Error creating cipher";
            return {};
        }

        output = cipher->negotiationOutput();
        return cipher;
    }
} // namespace FdoSecrets
