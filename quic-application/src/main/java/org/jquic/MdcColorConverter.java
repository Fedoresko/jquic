/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jquic;

import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

public class MdcColorConverter extends ClassicConverter {
    @Override
    public String convert(ILoggingEvent event) {
        String colorCode = event.getMDCPropertyMap().get("moduleColor");
        if (colorCode == null) {
            colorCode = "0"; // РЎС‚Р°РЅРґР°СЂС‚РЅС‹Р№ С†РІРµС‚
        }
        return "\u001B[" + colorCode + "m";
    }
}
