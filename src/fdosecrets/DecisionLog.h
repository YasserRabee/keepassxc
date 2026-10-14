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

#ifndef KEEPASSXC_FDOSECRETS_DECISIONLOG_H
#define KEEPASSXC_FDOSECRETS_DECISIONLOG_H

#include "core/Global.h"

#include <QJsonArray>
#include <QJsonObject>

class Entry;

namespace FdoSecrets
{
    struct ProcInfo;
    struct PeerInfo;

    /**
     * Fork-only: appends Secret Service access events as JSON lines to
     * $XDG_STATE_HOME/keepassxc/fdosecrets-log.jsonl (default ~/.local/state), readable by the user only.
     * Never logs secret values, and of command lines only the client's first two words.
     */
    namespace DecisionLog
    {
        void write(const QString& event, QJsonObject fields);

        QString decision(AuthDecision decision);
        QJsonObject entry(const Entry* entry);
        QJsonObject process(const ProcInfo& proc);
        // address, pid, executable and the command's first two words; with the chain, every
        // ancestor and how far "Remember while this runs" can reach, and where and why it stops
        QJsonObject client(const PeerInfo& info, bool withChain = false);
    } // namespace DecisionLog
} // namespace FdoSecrets

#endif // KEEPASSXC_FDOSECRETS_DECISIONLOG_H
