package com.lauriewired;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.*;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.net.URLDecoder;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;


@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ghidra.app.DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "HTTP server plugin",
	description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

	private HttpServer server;
	private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
	private static final String PORT_OPTION_NAME = "Server Port";
	private static final int DEFAULT_PORT = 8080;
	private Gson gson = null;

	public GhidraMCPPlugin(PluginTool tool) {
		super(tool);

		gson = new Gson();
		Msg.info(this, "GhidraMCPPlugin loading...");

		// Register the configuration option
		Options options = tool.getOptions(OPTION_CATEGORY_NAME);
		options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
			null, // No help location for now
			"The network port number the embedded HTTP server will listen on. " +
				"Requires Ghidra restart or plugin reload to take effect after changing.");

		try {
			startServer();
		} catch (IOException e) {
			Msg.error(this, "Failed to start HTTP server", e);
		}
		Msg.info(this, "GhidraMCPPlugin loaded!");
	}

	private void startServer() throws IOException {
		// Read the configured port
		Options options = tool.getOptions(OPTION_CATEGORY_NAME);
		int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

		// Stop existing server if running (e.g., if plugin is reloaded)
		if (server != null) {
			Msg.info(this, "Stopping existing HTTP server before starting new one.");
			server.stop(0);
			server = null;
		}

		server = HttpServer.create(new InetSocketAddress(port), 0);

		// Each listing endpoint uses offset & limit from query params:
		server.createContext("/methods", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100000);
			sendResponse(exchange, getAllFunctionNames(offset, limit));
		});

		server.createContext("/fun", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			var name = qparams.get("name");

			sendResponse(exchange, gson.toJson(getFunction(name)));
		});

		server.createContext("/classes", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, getAllClassNames(offset, limit));
		});

		server.createContext("/decompile", exchange -> {
			String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
			sendResponse(exchange, decompileFunctionByName(name));
		});

		server.createContext("/renameFunction", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String response = renameFunction(params.get("oldName"), params.get("newName"))
				? "Renamed successfully" : "Rename failed";
			sendResponse(exchange, response);
		});

		server.createContext("/renameData", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			renameDataAtAddress(params.get("address"), params.get("newName"));
			sendResponse(exchange, "Rename data attempted");
		});

		server.createContext("/renameVariable", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String functionName = params.get("functionName");
			String oldName = params.get("oldName");
			String newName = params.get("newName");
			String result = renameVariableInFunction(functionName, oldName, newName);
			sendResponse(exchange, result);
		});

		server.createContext("/segments", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, listSegments(offset, limit));
		});

		server.createContext("/imports", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, listImports(offset, limit));
		});

		server.createContext("/exports", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, listExports(offset, limit));
		});

		server.createContext("/namespaces", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, listNamespaces(offset, limit));
		});

		server.createContext("/data", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			boolean byteSourceOffset = parseBoolOrDefault(qparams.get("bytesourceoffset"), false);
			try {
				sendResponse(exchange, listDefinedData(offset, limit, byteSourceOffset));
			} catch (MemoryAccessException e) {
				throw new RuntimeException(e);
			}
		});

		server.createContext("/types", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			String kind = qparams.get("kind");
			String query = qparams.get("query");
			sendResponse(exchange, listDataTypes(offset, limit, kind, query));
		});

		server.createContext("/type", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			sendResponse(exchange, getDataTypeDetails(qparams.get("name")));
		});

		server.createContext("/renameDataType", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String response = renameDataType(params.get("oldName"), params.get("newName"));
			sendResponse(exchange, response);
		});

		server.createContext("/createStructure", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String response = createStructure(params.get("name"),
				parseIntOrDefault(params.get("size"), 0),
				params.get("categoryPath"));
			sendResponse(exchange, response);
		});

		server.createContext("/setStructureField", exchange -> {
			Map<String, String> params = parsePostParams(exchange);
			String response = setStructureField(
				params.get("structName"),
				parseIntOrDefault(params.get("offset"), 0),
				params.get("fieldType"),
				params.get("fieldName"),
				params.get("comment")
			);
			sendResponse(exchange, response);
		});

		server.createContext("/searchFunctions", exchange -> {
			Map<String, String> qparams = parseQueryParams(exchange);
			String searchTerm = qparams.get("query");
			int offset = parseIntOrDefault(qparams.get("offset"), 0);
			int limit = parseIntOrDefault(qparams.get("limit"), 100);
			sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
		});

		server.setExecutor(null);
		new Thread(() -> {
			try {
				server.start();
				Msg.info(this, "GhidraMCP HTTP server started on port " + port);
			} catch (Exception e) {
				Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
				server = null; // Ensure server isn't considered running
			}
		}, "GhidraMCP-HTTP-Server").start();
	}

	// ----------------------------------------------------------------------------------
	// Pagination-aware listing methods
	// ----------------------------------------------------------------------------------

	private String getAllFunctionNames(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		List<String> names = new ArrayList<>();
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			names.add(f.getName(true));
		}
		return gson.toJson(names);//paginateList(names, offset, limit);
	}

	private Fun getFunction(String name) {
		Program program = getCurrentProgram();
		//if (program == null) return ["No program loaded"];

		List<FunctionCall> calls = new ArrayList<>();

		FunctionManager fm = program.getFunctionManager();
		SymbolTable st = program.getSymbolTable();
		ReferenceManager rm = program.getReferenceManager();


		var fun = new Fun();
		for (Function f : fm.getFunctions(true)) {
			if (Objects.equals(f.getName(true), name)) {
				Address entry = f.getEntryPoint();
				var parameters = f.getParameters();


				Map<String, String> argRegs = new LinkedHashMap<>();

				for (var param : parameters)
					argRegs.put(param.getRegister().getName(), param.getName());
				// Get all references to this function
				for (Reference ref : rm.getReferencesTo(entry)) {
					Address callAddr = ref.getFromAddress();
					Instruction instr = program.getListing().getInstructionAt(callAddr);
					Function callingFunc = fm.getFunctionContaining(callAddr);

					if (instr == null || callingFunc == null || !instr.getMnemonicString().equalsIgnoreCase("CALL"))
						continue;

					FunctionCall fc = new FunctionCall();
					fc.callAddress = "0x%s".formatted(callAddr.toString());
					fc.fromFunction = callingFunc.getName(true);

					int stepsBack = 0;
					Map<String, Long> seenArgs = new LinkedHashMap<>();

					Instruction prev = instr.getPrevious();
					while (prev != null && stepsBack < 10) {
						if (prev.getNumOperands() >= 2 && prev.getOpObjects(0)[0] instanceof Register && prev.getOpObjects(1)[0] instanceof Scalar) {
							Register reg = (Register) prev.getOpObjects(0)[0];
							Scalar val = (Scalar) prev.getOpObjects(1)[0];
							String regName = reg.getName().toUpperCase();
							if (argRegs.containsKey(regName) && !seenArgs.containsKey(regName)) {
								seenArgs.put(argRegs.get(regName), val.getValue());
							}
						}

						prev = prev.getPrevious();
						stepsBack++;
					}

					fc.parameters.putAll(seenArgs);

					calls.add(fc);
				}

				fun.name = f.getName(true);
				fun.address = "0x%s".formatted(f.getEntryPoint().toString());
				fun.calls = calls;

				return fun;
			}
		}
		return null;
	}

	private String getAllClassNames(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		Set<String> classNames = new HashSet<>();
		for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
			Namespace ns = symbol.getParentNamespace();
			if (ns != null && !ns.isGlobal()) {
				classNames.add(ns.getName());
			}
		}
		// Convert set to list for pagination
		List<String> sorted = new ArrayList<>(classNames);

		Collections.sort(sorted);
		return paginateList(sorted, offset, limit);
	}

	private String listSegments(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		List<String> lines = new ArrayList<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
		}
		return paginateList(lines, offset, limit);
	}

	private String listImports(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		List<String> lines = new ArrayList<>();
		for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
			lines.add(symbol.getName() + " -> " + symbol.getAddress());
		}
		return paginateList(lines, offset, limit);
	}

	private String listExports(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		SymbolTable table = program.getSymbolTable();
		SymbolIterator it = table.getAllSymbols(true);

		List<String> lines = new ArrayList<>();
		while (it.hasNext()) {
			Symbol s = it.next();
			// On older Ghidra, "export" is recognized via isExternalEntryPoint()
			if (s.isExternalEntryPoint()) {
				lines.add(s.getName() + " -> " + s.getAddress());
			}
		}
		return paginateList(lines, offset, limit);
	}

	private String listNamespaces(int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		Set<String> namespaces = new HashSet<>();
		for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
			Namespace ns = symbol.getParentNamespace();
			if (ns != null && !(ns instanceof GlobalNamespace)) {
				namespaces.add(ns.getName());
			}
		}
		List<String> sorted = new ArrayList<>(namespaces);
		Collections.sort(sorted);
		return paginateList(sorted, offset, limit);
	}

	private String listDefinedData(int offset, int limit, boolean byteSourceOffset) throws MemoryAccessException {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		List<String> lines = new ArrayList<>();
		//for (MemoryBlock block : program.getMemory().getBlocks()) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace(); // or getAddressSpace("ram")
		Address addr = byteSourceOffset ? addressFromOffset(offset) : space.getAddress(offset);
		DataIterator it = program.getListing().getData(addr, true);
		int i = 0;
		while (it.hasNext()) {
			if (i > limit) break;
			Data data = it.next();
			//if (block.contains(data.getAddress())) {
			String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
			String valRepr = data.getDefaultValueRepresentation();
			lines.add(String.format("%s: %s = %s",
				data.getAddress(),
				escapeNonAscii(label),
				escapeNonAscii(valRepr)
			));

			var dataContainer = new DataContainer();
			dataContainer.name = escapeNonAscii(label);
			dataContainer.address = "0x%s".formatted(data.getAddress());
			dataContainer.data = Base64.getEncoder().encodeToString(data.getBytes());

			return gson.toJson(dataContainer);
			//}
			//i++;
		}
		//}
		return gson.toJson(lines);//paginateList(lines, offset, limit);
	}

	private Address addressFromOffset(long offset) {
		Program program = getCurrentProgram();

		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock block : blocks) {
			if (block.isInitialized() && block.isLoaded()) {
				long blockOffset = offset - block.getSourceInfos().getFirst().getFileBytesOffset();
				if (blockOffset >= 0 && blockOffset < block.getSize()) {
					return block.getStart().add(blockOffset);
				}
			}
		}
		return null; // Not found
	}

	private String searchFunctionsByName(String searchTerm, int offset, int limit) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";

		List<String> matches = new ArrayList<>();
		for (Function func : program.getFunctionManager().getFunctions(true)) {
			String name = func.getName();
			// simple substring match
			if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
				matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
			}
		}

		Collections.sort(matches);

		if (matches.isEmpty()) {
			return "No functions matching '" + searchTerm + "'";
		}
		return paginateList(matches, offset, limit);
	}

	private String listDataTypes(int offset, int limit, String kind, String query) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		String normalizedKind = kind == null ? "all" : kind.toLowerCase(Locale.ROOT);
		String normalizedQuery = query == null ? "" : query.toLowerCase(Locale.ROOT);
		List<Map<String, Object>> rows = new ArrayList<>();

		Iterator<DataType> allDataTypes = program.getDataTypeManager().getAllDataTypes();
		while (allDataTypes.hasNext()) {
			DataType dataType = allDataTypes.next();
			if (!matchesDataTypeKind(dataType, normalizedKind)) {
				continue;
			}
			String name = dataType.getName();
			String path = dataType.getPathName();
			if (!normalizedQuery.isEmpty() &&
				!name.toLowerCase(Locale.ROOT).contains(normalizedQuery) &&
				!path.toLowerCase(Locale.ROOT).contains(normalizedQuery)) {
				continue;
			}
			rows.add(summarizeDataType(dataType));
		}

		rows.sort(Comparator.comparing(row -> (String) row.get("path"), String.CASE_INSENSITIVE_ORDER));
		int start = Math.max(0, offset);
		int end = Math.min(rows.size(), start + Math.max(0, limit));
		if (start >= rows.size()) {
			return "[]";
		}
		return gson.toJson(rows.subList(start, end));
	}

	private String getDataTypeDetails(String name) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (name == null || name.isBlank()) return "Type name is required";

		DataType dataType = findDataTypeByName(program, name);
		if (dataType == null) {
			return "Data type not found";
		}
		return gson.toJson(describeDataType(dataType));
	}

	private String renameDataType(String oldName, String newName) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (oldName == null || oldName.isBlank() || newName == null || newName.isBlank()) {
			return "Type names are required";
		}

		AtomicReference<String> result = new AtomicReference<>("Rename failed");
		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename data type via HTTP");
				boolean success = false;
				try {
					DataType dataType = findDataTypeByName(program, oldName);
					if (dataType == null) {
						result.set("Data type not found");
						return;
					}
					dataType.setName(newName);
					result.set("Renamed successfully");
					success = true;
				} catch (Exception e) {
					Msg.error(this, "Error renaming data type", e);
					result.set("Error: " + e.getMessage());
				} finally {
					program.endTransaction(tx, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute data type rename on Swing thread", e);
			return "Error: " + e.getMessage();
		}
		return result.get();
	}

	private String createStructure(String name, int size, String categoryPath) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (name == null || name.isBlank()) return "Structure name is required";

		AtomicReference<String> result = new AtomicReference<>("Create failed");
		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Create structure via HTTP");
				boolean success = false;
				try {
					CategoryPath path = normalizeCategoryPath(categoryPath);
					StructureDataType newStructure = new StructureDataType(path, name, Math.max(size, 0));
					DataType resolved = program.getDataTypeManager().addDataType(newStructure,
						DataTypeConflictHandler.DEFAULT_HANDLER);
					result.set(gson.toJson(describeDataType(resolved)));
					success = true;
				} catch (Exception e) {
					Msg.error(this, "Error creating structure", e);
					result.set("Error: " + e.getMessage());
				} finally {
					program.endTransaction(tx, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute create structure on Swing thread", e);
			return "Error: " + e.getMessage();
		}
		return result.get();
	}

	private String setStructureField(String structName, int offset, String fieldTypeName, String fieldName,
			String comment) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		if (structName == null || structName.isBlank()) return "Structure name is required";
		if (fieldTypeName == null || fieldTypeName.isBlank()) return "Field type is required";

		AtomicReference<String> result = new AtomicReference<>("Field update failed");
		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Set structure field via HTTP");
				boolean success = false;
				try {
					DataType structType = findDataTypeByName(program, structName);
					if (!(structType instanceof Structure structure)) {
						result.set("Structure not found");
						return;
					}
					DataType fieldType = findDataTypeByName(program, fieldTypeName);
					if (fieldType == null) {
						result.set("Field type not found");
						return;
					}
					if (structure.isPackingEnabled()) {
						result.set("Packed structures are not supported");
						return;
					}
					String normalizedFieldName = fieldName == null || fieldName.isBlank() ? null : fieldName;
					String normalizedComment = comment == null || comment.isBlank() ? null : comment;
					int length = fieldType.getLength() > 0 ? fieldType.getLength() : -1;
					if (structure.isZeroLength() || offset >= structure.getLength()) {
						structure.insertAtOffset(offset, fieldType, length, normalizedFieldName, normalizedComment);
					} else {
						int fieldLength = Math.max(fieldType.getLength(), 1);
						int roomForData = structure.getLength() - (offset + fieldLength);
						if (roomForData < 0) {
							structure.growStructure(-roomForData);
						}
						structure.replaceAtOffset(offset, fieldType, length, normalizedFieldName, normalizedComment);
					}
					result.set(gson.toJson(describeDataType(structure)));
					success = true;
				} catch (Exception e) {
					Msg.error(this, "Error updating structure field", e);
					result.set("Error: " + e.getMessage());
				} finally {
					program.endTransaction(tx, success);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute structure field update on Swing thread", e);
			return "Error: " + e.getMessage();
		}
		return result.get();
	}

	private boolean matchesDataTypeKind(DataType dataType, String kind) {
		if (kind == null || kind.isEmpty() || "all".equals(kind)) {
			return true;
		}
		return switch (kind) {
			case "structure" -> dataType instanceof Structure;
			case "union" -> dataType instanceof Union;
			case "enum" -> dataType instanceof ghidra.program.model.data.Enum;
			case "typedef" -> dataType instanceof TypeDef;
			case "pointer" -> dataType instanceof Pointer;
			case "array" -> dataType instanceof Array;
			case "composite" -> dataType instanceof Composite;
			case "builtin" -> dataType.getDataTypeManager() instanceof BuiltInDataTypeManager;
			default -> true;
		};
	}

	private Map<String, Object> summarizeDataType(DataType dataType) {
		Map<String, Object> row = new LinkedHashMap<>();
		row.put("name", dataType.getName());
		row.put("path", dataType.getPathName());
		row.put("categoryPath", dataType.getCategoryPath().getPath());
		row.put("kind", classifyDataType(dataType));
		row.put("className", dataType.getClass().getSimpleName());
		row.put("length", dataType.getLength());
		return row;
	}

	private Map<String, Object> describeDataType(DataType dataType) {
		Map<String, Object> row = summarizeDataType(dataType);
		if (dataType instanceof TypeDef typeDef) {
			row.put("baseType", typeDef.getBaseDataType().getPathName());
		}
		if (dataType instanceof Pointer pointer && pointer.getDataType() != null) {
			row.put("pointsTo", pointer.getDataType().getPathName());
		}
		if (dataType instanceof Array array) {
			row.put("elementType", array.getDataType().getPathName());
			row.put("elementLength", array.getElementLength());
			row.put("numElements", array.getNumElements());
		}
		if (dataType instanceof Structure structure) {
			List<Map<String, Object>> components = new ArrayList<>();
			for (DataTypeComponent component : structure.getDefinedComponents()) {
				Map<String, Object> c = new LinkedHashMap<>();
				c.put("ordinal", component.getOrdinal());
				c.put("offset", component.getOffset());
				c.put("length", component.getLength());
				c.put("fieldName", component.getFieldName());
				c.put("comment", component.getComment());
				c.put("dataType", component.getDataType().getPathName());
				components.add(c);
			}
			row.put("components", components);
			row.put("packingEnabled", structure.isPackingEnabled());
		}
		if (dataType instanceof Union union) {
			List<Map<String, Object>> components = new ArrayList<>();
			for (DataTypeComponent component : union.getDefinedComponents()) {
				Map<String, Object> c = new LinkedHashMap<>();
				c.put("ordinal", component.getOrdinal());
				c.put("offset", component.getOffset());
				c.put("length", component.getLength());
				c.put("fieldName", component.getFieldName());
				c.put("comment", component.getComment());
				c.put("dataType", component.getDataType().getPathName());
				components.add(c);
			}
			row.put("components", components);
		}
		return row;
	}

	private String classifyDataType(DataType dataType) {
		if (dataType instanceof Structure) return "structure";
		if (dataType instanceof Union) return "union";
		if (dataType instanceof ghidra.program.model.data.Enum) return "enum";
		if (dataType instanceof TypeDef) return "typedef";
		if (dataType instanceof Pointer) return "pointer";
		if (dataType instanceof Array) return "array";
		if (dataType instanceof Composite) return "composite";
		return "datatype";
	}

	private CategoryPath normalizeCategoryPath(String categoryPath) {
		if (categoryPath == null || categoryPath.isBlank() || "/".equals(categoryPath)) {
			return CategoryPath.ROOT;
		}
		return categoryPath.startsWith("/") ? new CategoryPath(categoryPath) : new CategoryPath("/" + categoryPath);
	}

	private DataType findDataTypeByName(Program program, String name) {
		if (name == null || name.isBlank()) {
			return null;
		}
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		Iterator<DataType> allDataTypes = dataTypeManager.getAllDataTypes();
		DataType nameMatch = null;
		while (allDataTypes.hasNext()) {
			DataType dataType = allDataTypes.next();
			if (name.equals(dataType.getPathName())) {
				return dataType;
			}
			if (name.equals(dataType.getName()) && nameMatch == null) {
				nameMatch = dataType;
			}
		}
		return nameMatch;
	}

	// ----------------------------------------------------------------------------------
	// Logic for rename, decompile, etc.
	// ----------------------------------------------------------------------------------

	private String decompileFunctionByName(String name) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(program);
		for (Function func : program.getFunctionManager().getFunctions(true)) {
			if (func.getName().equals(name)) {
				DecompileResults result =
					decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
				if (result != null && result.decompileCompleted()) {
					return result.getDecompiledFunction().getC();
				} else {
					return "Decompilation failed";
				}
			}
		}
		return "Function not found";
	}

	private boolean renameFunction(String oldName, String newName) {
		Program program = getCurrentProgram();
		if (program == null) return false;

		AtomicBoolean successFlag = new AtomicBoolean(false);
		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename function via HTTP");
				try {
					for (Function func : program.getFunctionManager().getFunctions(true)) {
						if (func.getName().equals(oldName)) {
							func.setName(newName, SourceType.USER_DEFINED);
							successFlag.set(true);
							break;
						}
					}
				} catch (Exception e) {
					Msg.error(this, "Error renaming function", e);
				} finally {
					program.endTransaction(tx, successFlag.get());
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename on Swing thread", e);
		}
		return successFlag.get();
	}

	private void renameDataAtAddress(String addressStr, String newName) {
		Program program = getCurrentProgram();
		if (program == null) return;

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename data");
				try {
					Address addr = program.getAddressFactory().getAddress(addressStr);
					Listing listing = program.getListing();
					Data data = listing.getDefinedDataAt(addr);
					if (data != null) {
						SymbolTable symTable = program.getSymbolTable();
						Symbol symbol = symTable.getPrimarySymbol(addr);
						if (symbol != null) {
							symbol.setName(newName, SourceType.USER_DEFINED);
						} else {
							symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
						}
					}
				} catch (Exception e) {
					Msg.error(this, "Rename data error", e);
				} finally {
					program.endTransaction(tx, true);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Failed to execute rename data on Swing thread", e);
		}
	}

	private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
		Program program = getCurrentProgram();
		if (program == null) return "No program loaded";

		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(program);

		Function func = null;
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			if (f.getName().equals(functionName)) {
				func = f;
				break;
			}
		}

		if (func == null) {
			return "Function not found";
		}

		DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
		if (result == null || !result.decompileCompleted()) {
			return "Decompilation failed";
		}

		HighFunction highFunction = result.getHighFunction();
		if (highFunction == null) {
			return "Decompilation failed (no high function)";
		}

		LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
		if (localSymbolMap == null) {
			return "Decompilation failed (no local symbol map)";
		}

		HighSymbol highSymbol = null;
		Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
		while (symbols.hasNext()) {
			HighSymbol symbol = symbols.next();
			String symbolName = symbol.getName();

			if (symbolName.equals(oldVarName)) {
				highSymbol = symbol;
			}
			if (symbolName.equals(newVarName)) {
				return "Error: A variable with name '" + newVarName + "' already exists in this function";
			}
		}

		if (highSymbol == null) {
			return "Variable not found";
		}

		boolean commitRequired = checkFullCommit(highSymbol, highFunction);

		final HighSymbol finalHighSymbol = highSymbol;
		final Function finalFunction = func;
		AtomicBoolean successFlag = new AtomicBoolean(false);

		try {
			SwingUtilities.invokeAndWait(() -> {
				int tx = program.startTransaction("Rename variable");
				try {
					if (commitRequired) {
						HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
							ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
					}
					HighFunctionDBUtil.updateDBVariable(
						finalHighSymbol,
						newVarName,
						null,
						SourceType.USER_DEFINED
					);
					successFlag.set(true);
				} catch (Exception e) {
					Msg.error(this, "Failed to rename variable", e);
				} finally {
					program.endTransaction(tx, true);
				}
			});
		} catch (InterruptedException | InvocationTargetException e) {
			String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
			Msg.error(this, errorMsg, e);
			return errorMsg;
		}
		return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
	}

	/**
	 * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 *
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction  is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

	// ----------------------------------------------------------------------------------
	// Utility: parse query params, parse post params, pagination, etc.
	// ----------------------------------------------------------------------------------

	/**
	 * Parse query parameters from the URL, e.g. ?offset=10&limit=100
	 */
	private Map<String, String> parseQueryParams(HttpExchange exchange) {
		Map<String, String> result = new HashMap<>();
		String query = exchange.getRequestURI().getRawQuery(); // preserve encoded characters for explicit decoding
		if (query != null) {
			String[] pairs = query.split("&");
			for (String p : pairs) {
				String[] kv = p.split("=", 2);
				if (kv.length == 2) {
					String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
					String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
					result.put(key, value);
				}
			}
		}
		return result;
	}

	/**
	 * Parse post body form params, e.g. oldName=foo&newName=bar
	 */
	private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
		byte[] body = exchange.getRequestBody().readAllBytes();
		String bodyStr = new String(body, StandardCharsets.UTF_8);
		Map<String, String> params = new HashMap<>();
		for (String pair : bodyStr.split("&")) {
			String[] kv = pair.split("=", 2);
			if (kv.length == 2) {
				String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
				String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
				params.put(key, value);
			}
		}
		return params;
	}

	/**
	 * Convert a list of strings into one big newline-delimited string, applying offset & limit.
	 */
	private String paginateList(List<String> items, int offset, int limit) {
		int start = Math.max(0, offset);
		int end = Math.min(items.size(), offset + limit);

		if (start >= items.size()) {
			return ""; // no items in range
		}
		List<String> sub = items.subList(start, end);
		return String.join("\n", sub);
	}

	/**
	 * Parse an integer from a string, or return defaultValue if null/invalid.
	 */
	private int parseIntOrDefault(String val, int defaultValue) {
		if (val == null) return defaultValue;
		try {
			return Integer.parseInt(val);
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	/**
	 * Parse an integer from a string, or return defaultValue if null/invalid.
	 */
	private boolean parseBoolOrDefault(String val, boolean defaultValue) {
		if (val == null) return defaultValue;
		try {
			return Boolean.parseBoolean(val);
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	/**
	 * Escape non-ASCII chars to avoid potential decode issues.
	 */
	private String escapeNonAscii(String input) {
		if (input == null) return "";
		StringBuilder sb = new StringBuilder();
		for (char c : input.toCharArray()) {
			if (c >= 32 && c < 127) {
				sb.append(c);
			} else {
				sb.append("\\x");
				sb.append(Integer.toHexString(c & 0xFF));
			}
		}
		return sb.toString();
	}

	public Program getCurrentProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		return pm != null ? pm.getCurrentProgram() : null;
	}

	private void sendResponse(HttpExchange exchange, String response) throws IOException {
		byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		exchange.sendResponseHeaders(200, bytes.length);
		try (OutputStream os = exchange.getResponseBody()) {
			os.write(bytes);
		}
	}

	@Override
	public void dispose() {
		if (server != null) {
			Msg.info(this, "Stopping GhidraMCP HTTP server...");
			server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
			server = null; // Nullify the reference
			Msg.info(this, "GhidraMCP HTTP server stopped.");
		}
		super.dispose();
	}
}
