// Generated from DIDURL.g4 by ANTLR 4.9.1
package org.elastos.did.parser;
import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.misc.*;
import org.antlr.v4.runtime.tree.*;
import java.util.List;
import java.util.Iterator;
import java.util.ArrayList;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast"})
public class DIDURLParser extends Parser {
	static { RuntimeMetaData.checkVersion("4.9.1", RuntimeMetaData.VERSION); }

	protected static final DFA[] _decisionToDFA;
	protected static final PredictionContextCache _sharedContextCache =
		new PredictionContextCache();
	public static final int
		T__0=1, T__1=2, T__2=3, T__3=4, T__4=5, T__5=6, T__6=7, T__7=8, STRING=9, 
		HEX=10, SPACE=11;
	public static final int
		RULE_didurl = 0, RULE_did = 1, RULE_method = 2, RULE_methodSpecificString = 3, 
		RULE_params = 4, RULE_param = 5, RULE_paramQName = 6, RULE_paramMethod = 7, 
		RULE_paramName = 8, RULE_paramValue = 9, RULE_path = 10, RULE_query = 11, 
		RULE_queryParam = 12, RULE_queryParamName = 13, RULE_queryParamValue = 14, 
		RULE_frag = 15;
	private static String[] makeRuleNames() {
		return new String[] {
			"didurl", "did", "method", "methodSpecificString", "params", "param", 
			"paramQName", "paramMethod", "paramName", "paramValue", "path", "query", 
			"queryParam", "queryParamName", "queryParamValue", "frag"
		};
	}
	public static final String[] ruleNames = makeRuleNames();

	private static String[] makeLiteralNames() {
		return new String[] {
			null, "';'", "'/'", "'?'", "'#'", "'did'", "':'", "'='", "'&'"
		};
	}
	private static final String[] _LITERAL_NAMES = makeLiteralNames();
	private static String[] makeSymbolicNames() {
		return new String[] {
			null, null, null, null, null, null, null, null, null, "STRING", "HEX", 
			"SPACE"
		};
	}
	private static final String[] _SYMBOLIC_NAMES = makeSymbolicNames();
	public static final Vocabulary VOCABULARY = new VocabularyImpl(_LITERAL_NAMES, _SYMBOLIC_NAMES);

	/**
	 * @deprecated Use {@link #VOCABULARY} instead.
	 */
	@Deprecated
	public static final String[] tokenNames;
	static {
		tokenNames = new String[_SYMBOLIC_NAMES.length];
		for (int i = 0; i < tokenNames.length; i++) {
			tokenNames[i] = VOCABULARY.getLiteralName(i);
			if (tokenNames[i] == null) {
				tokenNames[i] = VOCABULARY.getSymbolicName(i);
			}

			if (tokenNames[i] == null) {
				tokenNames[i] = "<INVALID>";
			}
		}
	}

	@Override
	@Deprecated
	public String[] getTokenNames() {
		return tokenNames;
	}

	@Override

	public Vocabulary getVocabulary() {
		return VOCABULARY;
	}

	@Override
	public String getGrammarFileName() { return "DIDURL.g4"; }

	@Override
	public String[] getRuleNames() { return ruleNames; }

	@Override
	public String getSerializedATN() { return _serializedATN; }

	@Override
	public ATN getATN() { return _ATN; }

	public DIDURLParser(TokenStream input) {
		super(input);
		_interp = new ParserATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
	}

	public static class DidurlContext extends ParserRuleContext {
		public DidContext did() {
			return getRuleContext(DidContext.class,0);
		}
		public ParamsContext params() {
			return getRuleContext(ParamsContext.class,0);
		}
		public PathContext path() {
			return getRuleContext(PathContext.class,0);
		}
		public QueryContext query() {
			return getRuleContext(QueryContext.class,0);
		}
		public FragContext frag() {
			return getRuleContext(FragContext.class,0);
		}
		public TerminalNode SPACE() { return getToken(DIDURLParser.SPACE, 0); }
		public DidurlContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_didurl; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterDidurl(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitDidurl(this);
		}
	}

	public final DidurlContext didurl() throws RecognitionException {
		DidurlContext _localctx = new DidurlContext(_ctx, getState());
		enterRule(_localctx, 0, RULE_didurl);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(33);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__4) {
				{
				setState(32);
				did();
				}
			}

			setState(37);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__0) {
				{
				setState(35);
				match(T__0);
				setState(36);
				params();
				}
			}

			setState(41);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__1) {
				{
				setState(39);
				match(T__1);
				setState(40);
				path();
				}
			}

			setState(45);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__2) {
				{
				setState(43);
				match(T__2);
				setState(44);
				query();
				}
			}

			setState(49);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__3) {
				{
				setState(47);
				match(T__3);
				setState(48);
				frag();
				}
			}

			setState(52);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==SPACE) {
				{
				setState(51);
				match(SPACE);
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class DidContext extends ParserRuleContext {
		public MethodContext method() {
			return getRuleContext(MethodContext.class,0);
		}
		public MethodSpecificStringContext methodSpecificString() {
			return getRuleContext(MethodSpecificStringContext.class,0);
		}
		public DidContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_did; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterDid(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitDid(this);
		}
	}

	public final DidContext did() throws RecognitionException {
		DidContext _localctx = new DidContext(_ctx, getState());
		enterRule(_localctx, 2, RULE_did);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(54);
			match(T__4);
			setState(55);
			match(T__5);
			setState(56);
			method();
			setState(57);
			match(T__5);
			setState(58);
			methodSpecificString();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class MethodContext extends ParserRuleContext {
		public TerminalNode STRING() { return getToken(DIDURLParser.STRING, 0); }
		public MethodContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_method; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterMethod(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitMethod(this);
		}
	}

	public final MethodContext method() throws RecognitionException {
		MethodContext _localctx = new MethodContext(_ctx, getState());
		enterRule(_localctx, 4, RULE_method);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(60);
			match(STRING);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class MethodSpecificStringContext extends ParserRuleContext {
		public TerminalNode STRING() { return getToken(DIDURLParser.STRING, 0); }
		public MethodSpecificStringContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_methodSpecificString; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterMethodSpecificString(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitMethodSpecificString(this);
		}
	}

	public final MethodSpecificStringContext methodSpecificString() throws RecognitionException {
		MethodSpecificStringContext _localctx = new MethodSpecificStringContext(_ctx, getState());
		enterRule(_localctx, 6, RULE_methodSpecificString);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(62);
			match(STRING);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ParamsContext extends ParserRuleContext {
		public List<ParamContext> param() {
			return getRuleContexts(ParamContext.class);
		}
		public ParamContext param(int i) {
			return getRuleContext(ParamContext.class,i);
		}
		public ParamsContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_params; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterParams(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitParams(this);
		}
	}

	public final ParamsContext params() throws RecognitionException {
		ParamsContext _localctx = new ParamsContext(_ctx, getState());
		enterRule(_localctx, 8, RULE_params);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(64);
			param();
			setState(69);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==T__0) {
				{
				{
				setState(65);
				match(T__0);
				setState(66);
				param();
				}
				}
				setState(71);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ParamContext extends ParserRuleContext {
		public ParamQNameContext paramQName() {
			return getRuleContext(ParamQNameContext.class,0);
		}
		public ParamValueContext paramValue() {
			return getRuleContext(ParamValueContext.class,0);
		}
		public ParamContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_param; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterParam(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitParam(this);
		}
	}

	public final ParamContext param() throws RecognitionException {
		ParamContext _localctx = new ParamContext(_ctx, getState());
		enterRule(_localctx, 10, RULE_param);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(72);
			paramQName();
			setState(75);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__6) {
				{
				setState(73);
				match(T__6);
				setState(74);
				paramValue();
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ParamQNameContext extends ParserRuleContext {
		public ParamNameContext paramName() {
			return getRuleContext(ParamNameContext.class,0);
		}
		public ParamMethodContext paramMethod() {
			return getRuleContext(ParamMethodContext.class,0);
		}
		public ParamQNameContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_paramQName; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterParamQName(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitParamQName(this);
		}
	}

	public final ParamQNameContext paramQName() throws RecognitionException {
		ParamQNameContext _localctx = new ParamQNameContext(_ctx, getState());
		enterRule(_localctx, 12, RULE_paramQName);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(80);
			_errHandler.sync(this);
			switch ( getInterpreter().adaptivePredict(_input,8,_ctx) ) {
			case 1:
				{
				setState(77);
				paramMethod();
				setState(78);
				match(T__5);
				}
				break;
			}
			setState(82);
			paramName();
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ParamMethodContext extends ParserRuleContext {
		public TerminalNode STRING() { return getToken(DIDURLParser.STRING, 0); }
		public ParamMethodContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_paramMethod; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterParamMethod(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitParamMethod(this);
		}
	}

	public final ParamMethodContext paramMethod() throws RecognitionException {
		ParamMethodContext _localctx = new ParamMethodContext(_ctx, getState());
		enterRule(_localctx, 14, RULE_paramMethod);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(84);
			match(STRING);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ParamNameContext extends ParserRuleContext {
		public TerminalNode STRING() { return getToken(DIDURLParser.STRING, 0); }
		public ParamNameContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_paramName; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterParamName(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitParamName(this);
		}
	}

	public final ParamNameContext paramName() throws RecognitionException {
		ParamNameContext _localctx = new ParamNameContext(_ctx, getState());
		enterRule(_localctx, 16, RULE_paramName);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(86);
			match(STRING);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class ParamValueContext extends ParserRuleContext {
		public TerminalNode STRING() { return getToken(DIDURLParser.STRING, 0); }
		public ParamValueContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_paramValue; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterParamValue(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitParamValue(this);
		}
	}

	public final ParamValueContext paramValue() throws RecognitionException {
		ParamValueContext _localctx = new ParamValueContext(_ctx, getState());
		enterRule(_localctx, 18, RULE_paramValue);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(88);
			match(STRING);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class PathContext extends ParserRuleContext {
		public List<TerminalNode> STRING() { return getTokens(DIDURLParser.STRING); }
		public TerminalNode STRING(int i) {
			return getToken(DIDURLParser.STRING, i);
		}
		public PathContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_path; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterPath(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitPath(this);
		}
	}

	public final PathContext path() throws RecognitionException {
		PathContext _localctx = new PathContext(_ctx, getState());
		enterRule(_localctx, 20, RULE_path);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(90);
			match(STRING);
			setState(95);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==T__1) {
				{
				{
				setState(91);
				match(T__1);
				setState(92);
				match(STRING);
				}
				}
				setState(97);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class QueryContext extends ParserRuleContext {
		public List<QueryParamContext> queryParam() {
			return getRuleContexts(QueryParamContext.class);
		}
		public QueryParamContext queryParam(int i) {
			return getRuleContext(QueryParamContext.class,i);
		}
		public QueryContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_query; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterQuery(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitQuery(this);
		}
	}

	public final QueryContext query() throws RecognitionException {
		QueryContext _localctx = new QueryContext(_ctx, getState());
		enterRule(_localctx, 22, RULE_query);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(98);
			queryParam();
			setState(103);
			_errHandler.sync(this);
			_la = _input.LA(1);
			while (_la==T__7) {
				{
				{
				setState(99);
				match(T__7);
				setState(100);
				queryParam();
				}
				}
				setState(105);
				_errHandler.sync(this);
				_la = _input.LA(1);
			}
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class QueryParamContext extends ParserRuleContext {
		public QueryParamNameContext queryParamName() {
			return getRuleContext(QueryParamNameContext.class,0);
		}
		public QueryParamValueContext queryParamValue() {
			return getRuleContext(QueryParamValueContext.class,0);
		}
		public QueryParamContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_queryParam; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterQueryParam(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitQueryParam(this);
		}
	}

	public final QueryParamContext queryParam() throws RecognitionException {
		QueryParamContext _localctx = new QueryParamContext(_ctx, getState());
		enterRule(_localctx, 24, RULE_queryParam);
		int _la;
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(106);
			queryParamName();
			setState(109);
			_errHandler.sync(this);
			_la = _input.LA(1);
			if (_la==T__6) {
				{
				setState(107);
				match(T__6);
				setState(108);
				queryParamValue();
				}
			}

			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class QueryParamNameContext extends ParserRuleContext {
		public TerminalNode STRING() { return getToken(DIDURLParser.STRING, 0); }
		public QueryParamNameContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_queryParamName; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterQueryParamName(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitQueryParamName(this);
		}
	}

	public final QueryParamNameContext queryParamName() throws RecognitionException {
		QueryParamNameContext _localctx = new QueryParamNameContext(_ctx, getState());
		enterRule(_localctx, 26, RULE_queryParamName);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(111);
			match(STRING);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class QueryParamValueContext extends ParserRuleContext {
		public TerminalNode STRING() { return getToken(DIDURLParser.STRING, 0); }
		public QueryParamValueContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_queryParamValue; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterQueryParamValue(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitQueryParamValue(this);
		}
	}

	public final QueryParamValueContext queryParamValue() throws RecognitionException {
		QueryParamValueContext _localctx = new QueryParamValueContext(_ctx, getState());
		enterRule(_localctx, 28, RULE_queryParamValue);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(113);
			match(STRING);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static class FragContext extends ParserRuleContext {
		public TerminalNode STRING() { return getToken(DIDURLParser.STRING, 0); }
		public FragContext(ParserRuleContext parent, int invokingState) {
			super(parent, invokingState);
		}
		@Override public int getRuleIndex() { return RULE_frag; }
		@Override
		public void enterRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).enterFrag(this);
		}
		@Override
		public void exitRule(ParseTreeListener listener) {
			if ( listener instanceof DIDURLListener ) ((DIDURLListener)listener).exitFrag(this);
		}
	}

	public final FragContext frag() throws RecognitionException {
		FragContext _localctx = new FragContext(_ctx, getState());
		enterRule(_localctx, 30, RULE_frag);
		try {
			enterOuterAlt(_localctx, 1);
			{
			setState(115);
			match(STRING);
			}
		}
		catch (RecognitionException re) {
			_localctx.exception = re;
			_errHandler.reportError(this, re);
			_errHandler.recover(this, re);
		}
		finally {
			exitRule();
		}
		return _localctx;
	}

	public static final String _serializedATN =
		"\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\3\rx\4\2\t\2\4\3\t"+
		"\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7\4\b\t\b\4\t\t\t\4\n\t\n\4\13\t\13\4"+
		"\f\t\f\4\r\t\r\4\16\t\16\4\17\t\17\4\20\t\20\4\21\t\21\3\2\5\2$\n\2\3"+
		"\2\3\2\5\2(\n\2\3\2\3\2\5\2,\n\2\3\2\3\2\5\2\60\n\2\3\2\3\2\5\2\64\n\2"+
		"\3\2\5\2\67\n\2\3\3\3\3\3\3\3\3\3\3\3\3\3\4\3\4\3\5\3\5\3\6\3\6\3\6\7"+
		"\6F\n\6\f\6\16\6I\13\6\3\7\3\7\3\7\5\7N\n\7\3\b\3\b\3\b\5\bS\n\b\3\b\3"+
		"\b\3\t\3\t\3\n\3\n\3\13\3\13\3\f\3\f\3\f\7\f`\n\f\f\f\16\fc\13\f\3\r\3"+
		"\r\3\r\7\rh\n\r\f\r\16\rk\13\r\3\16\3\16\3\16\5\16p\n\16\3\17\3\17\3\20"+
		"\3\20\3\21\3\21\3\21\2\2\22\2\4\6\b\n\f\16\20\22\24\26\30\32\34\36 \2"+
		"\2\2s\2#\3\2\2\2\48\3\2\2\2\6>\3\2\2\2\b@\3\2\2\2\nB\3\2\2\2\fJ\3\2\2"+
		"\2\16R\3\2\2\2\20V\3\2\2\2\22X\3\2\2\2\24Z\3\2\2\2\26\\\3\2\2\2\30d\3"+
		"\2\2\2\32l\3\2\2\2\34q\3\2\2\2\36s\3\2\2\2 u\3\2\2\2\"$\5\4\3\2#\"\3\2"+
		"\2\2#$\3\2\2\2$\'\3\2\2\2%&\7\3\2\2&(\5\n\6\2\'%\3\2\2\2\'(\3\2\2\2(+"+
		"\3\2\2\2)*\7\4\2\2*,\5\26\f\2+)\3\2\2\2+,\3\2\2\2,/\3\2\2\2-.\7\5\2\2"+
		".\60\5\30\r\2/-\3\2\2\2/\60\3\2\2\2\60\63\3\2\2\2\61\62\7\6\2\2\62\64"+
		"\5 \21\2\63\61\3\2\2\2\63\64\3\2\2\2\64\66\3\2\2\2\65\67\7\r\2\2\66\65"+
		"\3\2\2\2\66\67\3\2\2\2\67\3\3\2\2\289\7\7\2\29:\7\b\2\2:;\5\6\4\2;<\7"+
		"\b\2\2<=\5\b\5\2=\5\3\2\2\2>?\7\13\2\2?\7\3\2\2\2@A\7\13\2\2A\t\3\2\2"+
		"\2BG\5\f\7\2CD\7\3\2\2DF\5\f\7\2EC\3\2\2\2FI\3\2\2\2GE\3\2\2\2GH\3\2\2"+
		"\2H\13\3\2\2\2IG\3\2\2\2JM\5\16\b\2KL\7\t\2\2LN\5\24\13\2MK\3\2\2\2MN"+
		"\3\2\2\2N\r\3\2\2\2OP\5\20\t\2PQ\7\b\2\2QS\3\2\2\2RO\3\2\2\2RS\3\2\2\2"+
		"ST\3\2\2\2TU\5\22\n\2U\17\3\2\2\2VW\7\13\2\2W\21\3\2\2\2XY\7\13\2\2Y\23"+
		"\3\2\2\2Z[\7\13\2\2[\25\3\2\2\2\\a\7\13\2\2]^\7\4\2\2^`\7\13\2\2_]\3\2"+
		"\2\2`c\3\2\2\2a_\3\2\2\2ab\3\2\2\2b\27\3\2\2\2ca\3\2\2\2di\5\32\16\2e"+
		"f\7\n\2\2fh\5\32\16\2ge\3\2\2\2hk\3\2\2\2ig\3\2\2\2ij\3\2\2\2j\31\3\2"+
		"\2\2ki\3\2\2\2lo\5\34\17\2mn\7\t\2\2np\5\36\20\2om\3\2\2\2op\3\2\2\2p"+
		"\33\3\2\2\2qr\7\13\2\2r\35\3\2\2\2st\7\13\2\2t\37\3\2\2\2uv\7\13\2\2v"+
		"!\3\2\2\2\16#\'+/\63\66GMRaio";
	public static final ATN _ATN =
		new ATNDeserializer().deserialize(_serializedATN.toCharArray());
	static {
		_decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
		for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
			_decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
		}
	}
}