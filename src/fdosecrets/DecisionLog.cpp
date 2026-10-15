/*
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

#include "DecisionLog.h"

#include "fdosecrets/dbus/DBusClient.h"

#include "core/Entry.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonDocument>

namespace FdoSecrets::DecisionLog
{
    void write(const QString& event, QJsonObject fields)
    {
        // ponytail: no rotation, a few hundred KB a day; rotate if it ever grows large
        static const auto path = [] {
            auto state = qEnvironmentVariable("XDG_STATE_HOME");
            if (!state.startsWith('/')) {
                state = QDir::homePath() + "/.local/state";
            }
            return state + "/keepassxc/fdosecrets-log.jsonl";
        }();

        fields.insert("t", QDateTime::currentDateTime().toString(Qt::ISODateWithMs));
        fields.insert("event", event);
        QDir().mkpath(QFileInfo(path).path());
        QFile file(path);
        if (!file.open(QIODevice::Append, QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
            return;
        }
        file.write(QJsonDocument(fields).toJson(QJsonDocument::Compact) + '\n');
    }

    QString decision(AuthDecision decision)
    {
        switch (decision) {
        case AuthDecision::Allowed:
            return "allowed";
        case AuthDecision::AllowedOnce:
            return "allowed-once";
        case AuthDecision::Denied:
            return "denied";
        case AuthDecision::DeniedOnce:
            return "denied-once";
        default:
            return "undecided";
        }
    }

    QJsonObject decisions(const QHash<QUuid, AuthDecision>& decisions)
    {
        QJsonObject obj;
        for (auto it = decisions.constBegin(); it != decisions.constEnd(); ++it) {
            obj.insert(it.key().toString(QUuid::WithoutBraces), decision(it.value()));
        }
        return obj;
    }

    QJsonObject entry(const Entry* entry)
    {
        if (!entry) {
            return {};
        }
        return {{"uuid", entry->uuid().toString(QUuid::WithoutBraces)}, {"title", entry->title()}};
    }

    QJsonObject process(const ProcInfo& proc)
    {
        return {{"pid", qint64(proc.pid)},
                {"start", QString::number(proc.startTime)},
                {"name", proc.name},
                {"exe", proc.exePath},
                {"tty", proc.tty},
                {"cgroup", proc.cgroup}};
    }

    QJsonObject client(const PeerInfo& info, bool withChain)
    {
        QJsonObject obj{{"address", info.address}, {"pid", qint64(info.pid)}};
        if (!info.hierarchy.isEmpty()) {
            const auto& self = info.hierarchy.front();
            obj.insert("exe", self.exePath);
            obj.insert("cmd", self.command.split(' ', Qt::SkipEmptyParts).mid(0, 2).join(' '));
        }
        if (!withChain) {
            return obj;
        }

        QJsonArray chain;
        for (const auto& proc : info.hierarchy) {
            chain << process(proc);
        }
        obj.insert("chain", chain);

        auto maxDepth = info.maxRememberDepth();
        obj.insert("maxDepth", maxDepth);
        QJsonArray offered;
        for (int i = 0; i <= maxDepth; ++i) {
            offered << QString("%1 %2").arg(info.hierarchy.at(i).name).arg(info.hierarchy.at(i).pid);
        }
        obj.insert("offered", offered);

        // the first ancestor the picker left out, and the broad reason
        QJsonObject stop;
        auto next = maxDepth + 1;
        if (maxDepth < 0) {
            stop.insert("reason", "client unidentified");
        } else if (next >= info.hierarchy.size()) {
            stop.insert("reason", "end of chain");
        } else {
            const auto& proc = info.hierarchy.at(next);
            stop.insert("depth", next);
            stop.insert("pid", qint64(proc.pid));
            stop.insert("name", proc.name);
            stop.insert("reason",
                        proc.pid <= 1                                   ? "PID 1"
                        : proc.startTime == 0 || proc.exePath.isEmpty() ? "unidentified"
                                                                        : "no shared pty or own cgroup with client");
        }
        obj.insert("stop", stop);
        return obj;
    }
} // namespace FdoSecrets::DecisionLog
