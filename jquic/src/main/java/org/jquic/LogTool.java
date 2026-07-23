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

import org.slf4j.Logger;
import org.slf4j.MDC;

public class LogTool {
    private final Logger logger;
    
    public LogTool(Logger logger) {
        this.logger = logger;
    }
    
    public void info(String color, String format, Object ... args) {
        // РџРµСЂРµРґР°РµРј РЅР°Р·РІР°РЅРёРµ ANSI-С†РІРµС‚Р° РёР»Рё РєР»СЋС‡РµРІРѕРµ СЃР»РѕРІРѕ
        MDC.put("moduleColor", color); // 35 вЂ” СЌС‚Рѕ РєРѕРґ Magenta (РїСѓСЂРїСѓСЂРЅС‹Р№) РІ ANSI

        logger.info(format, args);

        MDC.clear(); // Р’СЃРµРіРґР° РѕС‡РёС‰Р°Р№С‚Рµ MDC РІ Р±Р»РѕРєРµ finally!
    }

    public void info(String color, String format, Throwable e, Object ... args) {
        // РџРµСЂРµРґР°РµРј РЅР°Р·РІР°РЅРёРµ ANSI-С†РІРµС‚Р° РёР»Рё РєР»СЋС‡РµРІРѕРµ СЃР»РѕРІРѕ
        MDC.put("moduleColor", color); // 35 вЂ” СЌС‚Рѕ РєРѕРґ Magenta (РїСѓСЂРїСѓСЂРЅС‹Р№) РІ ANSI

        logger.info(format, e, args);

        MDC.clear(); // Р’СЃРµРіРґР° РѕС‡РёС‰Р°Р№С‚Рµ MDC РІ Р±Р»РѕРєРµ finally!
    }

    public void warn(String color, String format, Object ... args) {
        // РџРµСЂРµРґР°РµРј РЅР°Р·РІР°РЅРёРµ ANSI-С†РІРµС‚Р° РёР»Рё РєР»СЋС‡РµРІРѕРµ СЃР»РѕРІРѕ
        MDC.put("moduleColor", color); // 35 вЂ” СЌС‚Рѕ РєРѕРґ Magenta (РїСѓСЂРїСѓСЂРЅС‹Р№) РІ ANSI

        logger.warn(format, args);

        MDC.clear(); // Р’СЃРµРіРґР° РѕС‡РёС‰Р°Р№С‚Рµ MDC РІ Р±Р»РѕРєРµ finally!
    }

    public void warn(String color, String format, Throwable e, Object ... args) {
        // РџРµСЂРµРґР°РµРј РЅР°Р·РІР°РЅРёРµ ANSI-С†РІРµС‚Р° РёР»Рё РєР»СЋС‡РµРІРѕРµ СЃР»РѕРІРѕ
        MDC.put("moduleColor", color); // 35 вЂ” СЌС‚Рѕ РєРѕРґ Magenta (РїСѓСЂРїСѓСЂРЅС‹Р№) РІ ANSI

        logger.warn(format, e, args);

        MDC.clear(); // Р’СЃРµРіРґР° РѕС‡РёС‰Р°Р№С‚Рµ MDC РІ Р±Р»РѕРєРµ finally!
    }

    public void debug(String color, String format, Object ... args) {
        // РџРµСЂРµРґР°РµРј РЅР°Р·РІР°РЅРёРµ ANSI-С†РІРµС‚Р° РёР»Рё РєР»СЋС‡РµРІРѕРµ СЃР»РѕРІРѕ
        MDC.put("moduleColor", color); // 35 вЂ” СЌС‚Рѕ РєРѕРґ Magenta (РїСѓСЂРїСѓСЂРЅС‹Р№) РІ ANSI

        logger.debug(format, args);

        MDC.clear(); // Р’СЃРµРіРґР° РѕС‡РёС‰Р°Р№С‚Рµ MDC РІ Р±Р»РѕРєРµ finally!
    }

    public void debug(String color, String format, Throwable e, Object ... args) {
        // РџРµСЂРµРґР°РµРј РЅР°Р·РІР°РЅРёРµ ANSI-С†РІРµС‚Р° РёР»Рё РєР»СЋС‡РµРІРѕРµ СЃР»РѕРІРѕ
        MDC.put("moduleColor", color); // 35 вЂ” СЌС‚Рѕ РєРѕРґ Magenta (РїСѓСЂРїСѓСЂРЅС‹Р№) РІ ANSI

        logger.debug(format, e, args);

        MDC.clear(); // Р’СЃРµРіРґР° РѕС‡РёС‰Р°Р№С‚Рµ MDC РІ Р±Р»РѕРєРµ finally!
    }

    public void error(String color, String format, Object ... args) {
        // РџРµСЂРµРґР°РµРј РЅР°Р·РІР°РЅРёРµ ANSI-С†РІРµС‚Р° РёР»Рё РєР»СЋС‡РµРІРѕРµ СЃР»РѕРІРѕ
        MDC.put("moduleColor", color); // 35 вЂ” СЌС‚Рѕ РєРѕРґ Magenta (РїСѓСЂРїСѓСЂРЅС‹Р№) РІ ANSI

        logger.error(format, args);

        MDC.clear(); // Р’СЃРµРіРґР° РѕС‡РёС‰Р°Р№С‚Рµ MDC РІ Р±Р»РѕРєРµ finally!
    }

    public void error(String color, String format, Throwable e, Object ... args) {
        // РџРµСЂРµРґР°РµРј РЅР°Р·РІР°РЅРёРµ ANSI-С†РІРµС‚Р° РёР»Рё РєР»СЋС‡РµРІРѕРµ СЃР»РѕРІРѕ
        MDC.put("moduleColor", color); // 35 вЂ” СЌС‚Рѕ РєРѕРґ Magenta (РїСѓСЂРїСѓСЂРЅС‹Р№) РІ ANSI

        logger.error(format, e, args);

        MDC.clear(); // Р’СЃРµРіРґР° РѕС‡РёС‰Р°Р№С‚Рµ MDC РІ Р±Р»РѕРєРµ finally!
    }

}

