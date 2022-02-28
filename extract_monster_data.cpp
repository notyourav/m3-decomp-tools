#include <cassert>
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>

#include "battle/monster.h"

int main() {
    std::ifstream ifs("baserom.gba", std::ios::binary);
    ifs.seekg(0xD0D28);

    std::ofstream ofx("monsterData.cpp", std::ios::binary);

    std::vector<MonsterData> data;
    assert(sizeof(MonsterData) == 0x90);

    auto printField = [&](long value) -> std::string {
        std::stringstream ss;
        ss << std::hex << "\t0x" << value << ",";
        return ss.str();
    };

    for (int i = 0; i < 256; i++) {
        MonsterData m;
        ifs.read((char*)&m, sizeof(MonsterData));
        data.emplace_back(m);
    }

    ofx << "const MonsterData gMonsterData[] = {" << std::endl;
    for (auto& m : data) {
        ofx << "{";
        ofx << "/*      ID */" << printField(m.id);
        ofx << "/*   SMELL */" << printField(m.smell);
        ofx << "/*  OW SFX */" << printField(m.overworld_sfx);
        ofx << "/*      BG */" << printField(m.battle_bg);
        ofx << "/* ENC BGM */" << printField(m.encounter_bgm);
        ofx << "/* BTL BGM */" << printField(m.battle_bgm);
        ofx << "/* WIN BGM */" << printField(m.win_bgm);
        ofx << "/*     LVL */" << printField(m.level);
        ofx << "/*      HP */" << printField(m.hp);
        ofx << "/*      PP */" << printField(m.pp);
        ofx << "/*     OFF */" << printField(m.offense);
        ofx << "/*     DEF */" << printField(m.defense);
        ofx << "/*      IQ */" << printField(m.iq);
        ofx << "/*     SPD */" << printField(m.speed);
        ofx << "/*    KIND */" << printField(m.kindness);
        ofx << "/*  OFF SP */" << printField(m.offense_surprise);
        ofx << "/*  DEF SP */" << printField(m.defense_surprise);
        ofx << "/*   IQ SP */" << printField(m.iq_surprise);
        ofx << "/*  SPD SP */" << printField(m.speed_surprise);
        ofx << "/* KIND SP */" << printField(m.kindness_surprise);
        ofx << "/*POISON WK*/" << printField(m.weaknesses[0]);
        ofx << "/*PRLYZE WK*/" << printField(m.weaknesses[1]);
        ofx << "/* SLEEP WK*/" << printField(m.weaknesses[2]);
        ofx << "/*STRNGE WK*/" << printField(m.weaknesses[3]);
        ofx << "/*   CRY WK*/" << printField(m.weaknesses[4]);
        ofx << "/*   WEAK6 */" << printField(m.weaknesses[5]);
        ofx << "/*   WEAK7 */" << printField(m.weaknesses[6]);
        ofx << "/*   WEAK8 */" << printField(m.weaknesses[7]);
        ofx << "/* FLAME WK*/" << printField(m.weaknesses[8]);
        ofx << "/*FREEZE WK*/" << printField(m.weaknesses[9]);
        ofx << "/*  WEAK11 */" << printField(m.weaknesses[10]);
        ofx << "/*  DCMC WK*/" << printField(m.weaknesses[11]);
        ofx << "/*STAPLE WK*/" << printField(m.weaknesses[12]);
        ofx << "/*APOLGZ WK*/" << printField(m.weaknesses[13]);
        ofx << "/* LAUGH WK*/" << printField(m.weaknesses[14]);
        ofx << "/*  WEAK16 */" << printField(m.weaknesses[15]);
        ofx << "/*  FIRE WK*/" << printField(m.weaknesses[16]);
        ofx << "/*   ICE WK*/" << printField(m.weaknesses[17]);
        ofx << "/*LIGHTN WK*/" << printField(m.weaknesses[18]);
        ofx << "/*  BOMB WK*/" << printField(m.weaknesses[19]);
        ofx << "/*  SKILL1 */" << printField(m.skills[0]);
        ofx << "/*  SKILL2 */" << printField(m.skills[1]);
        ofx << "/*  SKILL3 */" << printField(m.skills[2]);
        ofx << "/*  SKILL4 */" << printField(m.skills[3]);
        ofx << "/*  SKILL5 */" << printField(m.skills[4]);
        ofx << "/*  SKILL6 */" << printField(m.skills[5]);
        ofx << "/*  SKILL7 */" << printField(m.skills[6]);
        ofx << "/*  SKILL8 */" << printField(m.skills[7]);
        ofx << "/* ATK SFX */" << printField(m.attack_sfx);
        ofx << "/* ENC MSG */" << printField(m.encounter_msg);
        ofx << "/* DIE MSG */" << printField(m.death_msg);
        ofx << "/* DIE SEQ */" << printField(m.death_anim);
        ofx << "/* BTL POS */" << printField(m.battle_pos);
        ofx << "/*  MEM Y1 */" << printField(m.memory_height[0]);
        ofx << "/*  MEM Y2 */" << printField(m.memory_height[1]);
        ofx << "/*  BTL Y1 */" << printField(m.battle_height[0]);
        ofx << "/*  BTL Y2 */" << printField(m.battle_height[1]);
        ofx << "/* MEM BCK */" << printField(m.memory_back_sprite);
        ofx << "/* BTL BCK */" << printField(m.battle_back_sprite);
        ofx << "/* LST SEQ */" << printField(m.death_anim_last);
        ofx << "/* ITM1 NO */" << printField(m.item1_no);
        ofx << "/*  ITM1 % */" << printField(m.item1_chance);
        ofx << "/* ITM1 UK */" << printField(m.item1_unk);
        ofx << "/* ITM2 NO */" << printField(m.item2_no);
        ofx << "/*  ITM2 % */" << printField(m.item2_chance);
        ofx << "/* ITM2 UK */" << printField(m.item2_unk);
        ofx << "/* ITM3 NO */" << printField(m.item3_no);
        ofx << "/*  ITM3 % */" << printField(m.item3_chance);
        ofx << "/* ITM3 UK */" << printField(m.item3_unk);
        ofx << "/*     EXP */" << printField(m.experience);
        ofx << "/*   MONEY */" << printField(m.money);
        ofx << "/* WK1 MSG */" << printField(m.smell_weaknesses[0]);
        ofx << "/* WK2 MSG */" << printField(m.smell_weaknesses[1]);

        // ofx << " /*      ID */" << printField(m.id);
        // ofx << " /* PP COST */" << printField(m.pp_cost);
        // ofx << " /* RECOLOR */" << printField(m.recolor_value);
        // ofx << " /* HAS SFX */" << "\t0x" << std::hex << m.has_sound << ",";
        // ofx << " /*  EFFECT */" << printField(m.move.effect);
        // ofx << " /* ELEMENT */" << printField(m.move.element);
        // ofx << " /*  TARGET */" << printField(m.move.target);
        // ofx << " /*    UNK1 */" << printField(m.move.unk1);
        // ofx << " /* ATK MUL */" << printField(m.move.atk_mult);
        // ofx << " /* HEAL LO */" << printField(m.move.heal_lo);
        // ofx << " /* HEAL HI */" << printField(m.move.heal_hi);
        // ofx << " /*  STATUS */" << printField(m.move.ailment);
        // ofx << " /* STATUS% */" << printField(m.move.ailment_chance);
        // ofx << " /*  ACTION */" << printField(m.move.action);
        // ofx << " /*    PRIO */" << printField(m.move.priority);
        // ofx << " /*  MSG NO */" << printField(m.move.msg_no);
        // ofx << " /* DIMMING */" << printField(m.move.has_dim);
        // ofx << " /*  SEQ NO */" << printField(m.move.anim_no);
        // ofx << " /* SEQ NO2 */" << printField(m.move.anim_success);
        // ofx << " /*   SOUND */" << printField(m.move.sfx_no);
        // ofx << " /*  MISS % */" << printField(m.move.miss_chance);
        // ofx << " /* SMASH % */" << printField(m.move.smash_chance);
        // ofx << " /* REDIR 1 */" << printField(m.move.redirectable);
        // ofx << " /* REDIR 2 */" << printField(m.move.redirectable2);
        // ofx << "},";
        ofx << "}," << std::endl;
    }
    ofx << "};" << std::endl;

    return 0;
}
