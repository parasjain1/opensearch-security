package org.opensearch.security.bwc;

public class Indices {

    static final String FIRST_INDEX_ID_SONG_1 = "INDEX_1_S1";
    static final String FIRST_INDEX_ID_SONG_2 = "INDEX_1_S2";
    static final String FIRST_INDEX_ID_SONG_3 = "INDEX_1_S3";
    static final String FIRST_INDEX_ID_SONG_4 = "INDEX_1_S4";
    static final String FIRST_INDEX_ID_SONG_5 = "INDEX_1_S5";
    static final String FIRST_INDEX_ID_SONG_6 = "INDEX_1_S6";
    static final String SECOND_INDEX_ID_SONG_1 = "INDEX_2_S1";
    static final String SECOND_INDEX_ID_SONG_2 = "INDEX_2_S2";
    static final String SECOND_INDEX_ID_SONG_3 = "INDEX_2_S3";
    static final String SECOND_INDEX_ID_SONG_4 = "INDEX_2_S4";

    static final String INDEX_NAME_SUFFIX = "-test-index";
    static final String FIRST_INDEX_NAME = "first".concat(INDEX_NAME_SUFFIX);
    static final String SECOND_INDEX_NAME = "second".concat(INDEX_NAME_SUFFIX);
    static final String FIRST_INDEX_ALIAS = FIRST_INDEX_NAME.concat("-alias");
    static final String SECOND_INDEX_ALIAS = SECOND_INDEX_NAME.concat("-alias");
    static final String FIRST_INDEX_ALIAS_FILTERED_BY_NEXT_SONG_TITLE = FIRST_INDEX_NAME.concat("-filtered-by-next-song-title");
    static final String FIRST_INDEX_ALIAS_FILTERED_BY_TWINS_ARTIST = FIRST_INDEX_NAME.concat("-filtered-by-twins-artist");
    static final String FIRST_INDEX_ALIAS_FILTERED_BY_FIRST_ARTIST = FIRST_INDEX_NAME.concat("-filtered-by-first-artist");
    static final String ALL_INDICES_ALIAS = "_all";

}
